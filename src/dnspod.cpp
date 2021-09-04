#include <sys/time.h>
#include <sys/timerfd.h>

#include <atomic>
#include <chrono>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <map>
#include <regex>
#include <set>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <thread>
#include <time.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif

#include <http/httplib.h>

static std::string get_current_time();

#define __LOG_MSG(fmt, ...) fprintf(stderr, "%s: " fmt "%s", get_current_time().c_str(), __VA_ARGS__)
#define LOG_MSG(...) __LOG_MSG(__VA_ARGS__, "\n")

enum http_method
{
    kGET = 0,
    kPUT,
    kPOST,
    kDELETE
};

struct query_ip_config
{
    uint16_t port      = 443;
    http_method method = http_method::kGET;
    std::string host   = "ifconfig.me";
    std::string path   = "/ip";
    std::string key    = "";
};

struct record_info
{
    std::string record_id;
    std::string record_sub_domain;
    std::string record_type;
    std::string record_value;
    std::string ttl;
    inline bool operator<(const record_info& other) const
    {
        return record_id < other.record_id || record_sub_domain < other.record_sub_domain
            || record_type < other.record_type || record_value < other.record_value;
    }
};

struct domain_info
{
    std::string domain_id;
    std::string domain;
    std::set<record_info> record_info_set;
    std::vector<record_info> record_info_vec;
};

struct do_on_exit
{
    explicit do_on_exit(std::function<void(void)> hd) : do_on_exit_hd_(hd) {}
    ~do_on_exit()
    {
        if (do_on_exit_hd_)
        {
            do_on_exit_hd_();
        }
    }

private:
    std::function<void(void)> do_on_exit_hd_;
};

template <typename T> static T GetValue(const nlohmann::json& js, const std::string& key, const T&& default_value);

static std::string GetValue(const nlohmann::json& js, const std::string& key, const char* default_value);

static void wrap_request_str(const std::string& key, const std::string& value, std::string& req_str);

static bool http_sync_request(const http_method method,
                              const std::string& host,
                              const uint16_t port,
                              const std::string& path,
                              const httplib::Headers& header,
                              const std::string& content_type,
                              const std::string& request,
                              std::string& resp_str);

static bool dnspod_api(const std::string& path, std::string& request, nlohmann::json& resp_js);

static std::string get_current_ip();

static void get_domain_list(std::map<std::string, domain_info>& domain_info_map);

static bool update_dns_record(const std::string& domain_id,
                              const std::string& record_id,
                              const std::string& sub_domain,
                              const std::string& record_type,
                              const std::string& ip,
                              const std::string& ttl);

static void update_dns_loop(const nlohmann::json& domain_list_js, std::map<std::string, domain_info>& domain_info_map);

static std::string s_g_dnspod_token = "";

static query_ip_config s_g_query_ip_config;

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        LOG_MSG("the config path must set");
        return 1;
    }

    try
    {
        std::ifstream ifs(argv[1]);
        if (!ifs)
        {
            LOG_MSG("open config: %s failed", argv[1]);
            return 1;
        }

        nlohmann::json config_json = nlohmann::json::parse(ifs, nullptr, true, true);

        s_g_dnspod_token = GetValue(config_json, "token", "");
        if (s_g_dnspod_token.empty())
        {
            LOG_MSG("token is empty");
            return 1;
        }

        auto domain_it = config_json.find("domain_list");
        if (domain_it == config_json.end() || !domain_it->is_array())
        {
            LOG_MSG("domain_list invalid");
            return 1;
        }

        auto query_it = config_json.find("query_ip_host");
        if (query_it != config_json.end() && query_it->is_object())
        {
            std::string method = GetValue(*query_it, "method", "GET");
            if (method == "GET")
            {
                s_g_query_ip_config.method = http_method::kGET;
            }
            else if (method == "POST")
            {
                s_g_query_ip_config.method = http_method::kPOST;
            }
            else if (method == "PUT")
            {
                s_g_query_ip_config.method = http_method::kPUT;
            }
            else if (method == "DELETE")
            {
                s_g_query_ip_config.method = http_method::kDELETE;
            }

            s_g_query_ip_config.port = GetValue(*query_it, "port", 443);
            s_g_query_ip_config.host = GetValue(*query_it, "host", "ifconfig.me");
            s_g_query_ip_config.path = GetValue(*query_it, "path", "/ip");
            s_g_query_ip_config.key  = GetValue(*query_it, "key", "");
        }

        std::map<std::string, domain_info> domain_info_map;
        get_domain_list(domain_info_map);
        if (domain_info_map.empty())
        {
            return 1;
        }

        update_dns_loop(*domain_it, domain_info_map);
    }
    catch (const std::exception& err)
    {
        LOG_MSG("main, catch exception:%s", err.what());
        return 1;
    }
}

void sig_handler(int sig, siginfo_t* info, void*)
{
    if (sig == SIGUSR1 && info != nullptr && info->si_int == 0x1234)
    {
        pthread_exit(nullptr);
    }
}

static void update_dns_loop(const nlohmann::json& domain_list_js, std::map<std::string, domain_info>& domain_info_map)
{
    try
    {
        int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (timer_fd < 0)
        {
            LOG_MSG("timerfd_create failed, errno:%d, desc:%s", errno, strerror(errno));
            return;
        }

        do_on_exit on_exit(
            [&timer_fd]()
            {
                if (timer_fd > 0)
                {
                    close(timer_fd);
                }
            });

        struct itimerspec its;
        memset(&its, 0, sizeof(struct itimerspec));
        its.it_interval.tv_sec = 0;
        its.it_value.tv_sec    = 600;
        if (timerfd_settime(timer_fd, 0, &its, nullptr) != 0)
        {
            LOG_MSG("timerfd_settime failed, errno:%d, desc:%s", errno, strerror(errno));
            return;
        }

        std::string current_ip;
        std::regex ip_reg("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}");

        std::atomic_uint64_t loop_times = {0};

        auto main_loop = [&]()
        {
            struct sigaction sa;
            memset(&sa, 0, sizeof(sa));
            sa.sa_flags     = SA_RESTART | SA_SIGINFO;
            sa.sa_sigaction = sig_handler;
            if (sigaction(SIGUSR1, &sa, nullptr) != 0)
            {
                LOG_MSG("sigaction failed, errno:%d, desc:%s", errno, strerror(errno));
                _exit(1);
            }

            while (true)
            {
                uint64_t count = 0;
                ssize_t err    = 0;
                err            = read(timer_fd, &count, sizeof(uint64_t));
                if (err == sizeof(uint64_t))
                {
                    if (timerfd_settime(timer_fd, 0, &its, nullptr) != 0)
                    {
                        LOG_MSG("timerfd_settime failed, errno:%d, desc:%s", errno, strerror(errno));
                        return;
                    }

                    LOG_MSG("get domain info");
                    while (true)
                    {
                        get_domain_list(domain_info_map);
                        if (domain_info_map.empty())
                        {
                            LOG_MSG("try domain list failed");
                            std::this_thread::sleep_for(std::chrono::seconds(10));
                            continue;
                        }

                        break;
                    }
                }

                current_ip = get_current_ip();
                if (std::regex_match(current_ip, ip_reg))
                {
                    // iterator user domain list
                    for (const auto& item : domain_list_js)
                    {
                        if (!item.is_object())
                        {
                            LOG_MSG("invalid domain_list: %s", domain_list_js.dump().c_str());
                            exit(1);
                        }

                        auto domain     = GetValue(item, "domain", "");
                        auto sub_domain = GetValue(item, "sub_domain", "");
                        if (domain.empty() || sub_domain.empty())
                        {
                            LOG_MSG("invalid domain_list: %s", domain_list_js.dump().c_str());
                            exit(1);
                        }
                        auto ttl = GetValue(item, "ttl", "600");
                        // domain
                        auto it = domain_info_map.find(domain);
                        if (it == domain_info_map.end())
                        {
                            LOG_MSG("cann't find domain: %s at dnspod list", domain.c_str());
                            exit(1);
                        }

                        // iterator record list
                        // update dns record
                        for (auto& record : it->second.record_info_vec)
                        {
                            // the sub domain must match
                            if (record.record_id.empty() || record.record_sub_domain.empty()
                                || record.record_sub_domain != sub_domain || current_ip == record.record_value)
                            {
                                continue;
                            }

                            // update dns record
                            if (update_dns_record(it->second.domain_id,
                                                  record.record_id,
                                                  sub_domain,
                                                  record.record_type,
                                                  current_ip,
                                                  ttl))
                            {
                                LOG_MSG("update domain: %s to: %s", domain.c_str(), current_ip.c_str());
                                record.record_value = current_ip;
                            }
                        }
                    }
                }

                std::this_thread::sleep_for(std::chrono::seconds(5));
                ++loop_times;
            }
        };

        uint64_t last_loop_times = 0;
        std::thread thread;
    retry:
        thread = std::thread(main_loop);
        while (true)
        {
            std::this_thread::sleep_for(std::chrono::seconds(5 * 60));
            auto now_loop_time = loop_times.load();
            if (last_loop_times == now_loop_time)
            {
                union sigval sval;
                sval.sival_int = 0x1234;
                if (pthread_sigqueue(thread.native_handle(), SIGUSR1, sval) != 0)
                {
                    LOG_MSG("pthread_sigqueue failed, errno:%d, desc:%s", errno, strerror(errno));
                    _exit(1);
                }
                thread.join();
                LOG_MSG("kill blocked thread and retry");
                goto retry;
            }
            else
            {
                last_loop_times = now_loop_time;
            }
        }
    }
    catch (const std::exception& err)
    {
        LOG_MSG("update_dns_loop catch exception : %s", err.what());
    }
}

template <typename T> static T GetValue(const nlohmann::json& js, const std::string& key, const T&& default_value)
{
    auto it = js.find(key);
    if (it == js.end())
    {
        return default_value;
    }

    try
    {
        return it->get<T>();
    }
    catch (...)
    {
        return default_value;
    }
}

static std::string GetValue(const nlohmann::json& js, const std::string& key, const char* default_value)
{
    auto it = js.find(key);
    if (it == js.end())
    {
        return std::string(default_value);
    }

    try
    {
        if (it->is_string())
        {
            return *it;
        }
        else if (it->is_boolean())
        {
            return bool(*it) ? "true" : "false";
        }
        else if (it->is_number_float())
        {
            return std::to_string(double(*it));
        }
        else if (it->is_number_unsigned())
        {
            return std::to_string(uint64_t(*it));
        }
        else if (it->is_number())
        {
            return std::to_string(int64_t(*it));
        }
        else
        {
            return std::string(default_value);
        }
    }
    catch (...)
    {
        return std::string(default_value);
    }
}

static bool http_sync_request(const http_method method,
                              const std::string& host,
                              const uint16_t port,
                              const std::string& path,
                              const httplib::Headers& header,
                              const std::string& content_type,
                              const std::string& request,
                              std::string& resp_str)
{
    try
    {
        httplib::SSLClient cli(host, port);
        cli.set_read_timeout(5, 0);
        cli.set_write_timeout(5, 0);
        cli.set_connection_timeout(5, 0);
        cli.enable_server_certificate_verification(true);
        auto ctx_ssl                      = cli.ssl_context();
        static const unsigned char alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        if (SSL_CTX_set_alpn_protos(ctx_ssl, alpn, sizeof(alpn)) != 0)
        {
            LOG_MSG("SSL_CTX_set_alpn_protos failed");
            return false;
        }

        httplib::Result resp(nullptr, httplib::Error::Unknown);
        switch (method)
        {
        case http_method::kGET:
            resp = cli.Get(path.c_str(), header);
            break;
        case http_method::kPUT:
            resp = cli.Put(path.c_str(), header, request, content_type.c_str());
            break;
        case http_method::kPOST:
            resp = cli.Post(path.c_str(), header, request, content_type.c_str());
            break;
        case http_method::kDELETE:
            resp = cli.Delete(path.c_str(), header);
            break;

        default:
            return false;
        }

        if (resp)
        {
            resp_str = resp->body;
            return true;
        }
        else
        {
            return false;
        }
    }
    catch (const std::exception& err)
    {
        LOG_MSG("err:%s", err.what());
        return false;
    }
}

static bool dnspod_api(const std::string& path, std::string& request, nlohmann::json& resp_js)
{
    try
    {
        static const std::string dnspod_api_host = "dnsapi.cn";
        static const std::string agent           = "AnripDdns/6.0.0(mail@anrip.com)";
        wrap_request_str("login_token", s_g_dnspod_token, request);
        wrap_request_str("format", "json", request);
        wrap_request_str("lang", "cn", request);

        httplib::Headers header;
        header.emplace("User-Agent", agent);
        header.emplace("Host", dnspod_api_host);
        std::string resp;
        http_sync_request(
            http_method::kPOST, dnspod_api_host, 443, path, header, "application/x-www-form-urlencoded", request, resp);
        resp_js = nlohmann::json::parse(resp, nullptr, false);
        auto it = resp_js.find("status");
        if (it == resp_js.end() || !it->is_object())
        {
            LOG_MSG("dnspod_api failed, invalid resp: %s", resp.c_str());
            return false;
        }

        if (GetValue(*it, "code", "-1") != "1")
        {
            LOG_MSG("dnspod_api failed, resp: %s", resp.c_str());
            return false;
        }
        else
        {
            return true;
        }
    }
    catch (const std::exception& err)
    {
        LOG_MSG("dnspod_api failed, catch exception:%s", err.what());
        return false;
    }
}

static std::string get_current_ip()
{
    std::string host_ip;
    http_sync_request(s_g_query_ip_config.method,
                      s_g_query_ip_config.host,
                      s_g_query_ip_config.port,
                      s_g_query_ip_config.path,
                      httplib::Headers(),
                      "application/x-www-form-urlencoded",
                      s_g_query_ip_config.key,
                      host_ip);
    return host_ip;
}

static void get_domain_list(std::map<std::string, domain_info>& domain_info_map)
{
    try
    {
        domain_info_map.clear();
        std::string req_str;
        nlohmann::json resp_js;
        if (!dnspod_api("/Domain.List", req_str, resp_js))  // Domain.List
        {
            LOG_MSG("get domain list failed");
            return;
        }

        auto it = resp_js.find("domains");
        if (it != resp_js.end() && it->is_array())
        {
            for (auto& item : *it)
            {
                if (!item.is_object())
                {
                    continue;
                }

                domain_info domain;
                std::string domain_str = GetValue(item, "name", "");
                domain.domain          = domain_str;

                domain.domain_id = GetValue(item, "id", "");
                if (domain.domain.empty() || domain.domain_id.empty())
                {
                    continue;
                }

                std::string req_str;
                wrap_request_str("domain_id", domain.domain_id, req_str);
                nlohmann::json resp_js;
                if (!dnspod_api("/Record.List", req_str, resp_js))  // Record.List
                {
                    LOG_MSG("get domain: %s record list failed", domain_str.c_str());
                    continue;
                }

                auto it = resp_js.find("records");
                if (it != resp_js.end() && it->is_array())
                {
                    for (auto& item : *it)
                    {
                        if (!item.is_object())
                        {
                            continue;
                        }

                        record_info record;
                        record.record_id         = GetValue(item, "id", "");
                        record.record_sub_domain = GetValue(item, "name", "");  //@, www,
                        record.record_type       = GetValue(item, "type", "A");  // A, AAAA
                        record.record_value      = GetValue(item, "value", "");  // IP
                        record.ttl               = GetValue(item, "ttl", "");  // ttl
                        domain.record_info_set.insert(std::move(record));
                    }
                }

                domain.record_info_vec.reserve(domain.record_info_set.size());
                std::copy(domain.record_info_set.begin(),
                          domain.record_info_set.end(),
                          std::back_inserter(domain.record_info_vec));
                domain_info_map.emplace(std::move(domain_str), std::move(domain));
            }
        }
    }
    catch (const std::exception& err)
    {
        LOG_MSG("get_domain_list failed, catch exception:%s", err.what());
    }
}

static bool update_dns_record(const std::string& domain_id,
                              const std::string& record_id,
                              const std::string& sub_domain,
                              const std::string& record_type,
                              const std::string& ip,
                              const std::string& ttl)
{
    std::string req_str;
    wrap_request_str("domain_id", domain_id, req_str);
    wrap_request_str("record_id", record_id, req_str);
    wrap_request_str("sub_domain", sub_domain, req_str);
    wrap_request_str("record_type", record_type, req_str);
    wrap_request_str("value", ip, req_str);
    wrap_request_str("ttl", ttl, req_str);
    wrap_request_str("record_line", "%e9%bb%98%e8%ae%a4", req_str);
    nlohmann::json resp_js;
    if (!dnspod_api("/Record.Modify", req_str, resp_js))
    {
        LOG_MSG("update_dns_record failed");
        return false;
    }
    return true;
}

static std::string get_current_time()
{
    try
    {
        auto now      = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::string tm_str(ctime(&t));
        tm_str.pop_back();
        return tm_str;
    }
    catch (...)
    {
        return "";
    }
}

static void wrap_request_str(const std::string& key, const std::string& value, std::string& req_str)
{
    if (!req_str.empty())
    {
        req_str.append("&");
    }
    req_str.append(key);
    req_str.append("=");
    req_str.append(value);
}
