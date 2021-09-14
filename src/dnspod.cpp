// system
#include <fcntl.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <unistd.h>

// c std
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <ctime>

// cpp std
#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <regex>
#include <set>
#include <string>
#include <thread>

// 3rd
#include <http/httplib.h>
#include <nlohmann/json.hpp>

static std::string get_time_str();
#define __LOG_MSG(fmt, ...) fprintf(stdout, "%s " fmt "%s", get_time_str().c_str(), __VA_ARGS__)
#define LOG_MSG(...) __LOG_MSG(__VA_ARGS__, "\n")

struct config
{
    enum http_method
    {
        kGET = 0,
        kPUT,
        kPOST,
        kDELETE
    };

    std::string dnspod_token;
    struct
    {
        bool is_cmd        = false;
        uint16_t port      = 443;
        uint32_t interval  = 10;
        http_method method = http_method::kGET;
        std::string cmd;
        std::string body;
        std::string host = "ifconfig.me";
        std::string path = "/ip";
    } query_self_info;

    struct domain_type
    {
        std::string domain;
        std::string sub_domain;
        std::string ttl;
    };
    std::vector<domain_type> domain_list;
};

struct record_info
{
    std::string id;
    std::string sub_domain;
    std::string type;
    std::string value;
    std::string ttl;
    inline bool operator<(const record_info& other) const
    {
        return id < other.id || sub_domain < other.sub_domain || type < other.type || value < other.value;
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
    do_on_exit(const do_on_exit&) = delete;
    do_on_exit& operator=(const do_on_exit&) = delete;

    do_on_exit(do_on_exit&& other) noexcept : do_on_exit_hd_(std::move(other.do_on_exit_hd_))
    {
        other.do_on_exit_hd_ = nullptr;
    }

    do_on_exit& operator=(do_on_exit&& other) noexcept
    {
        if (this != &other)
        {
            do_on_exit_hd_       = std::move(other.do_on_exit_hd_);
            other.do_on_exit_hd_ = nullptr;
        }

        return *this;
    }

    explicit do_on_exit(std::function<void(void)> hd) : do_on_exit_hd_(std::move(hd)) {}
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

static bool http_sync_request(const config::http_method method,
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

static void update_dns_loop(std::map<std::string, domain_info>& domain_info_map);

static config global_config;

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

        global_config.dnspod_token = GetValue(config_json, "token", "");
        if (global_config.dnspod_token.empty())
        {
            LOG_MSG("dnspod token is empty");
            return 1;
        }

        auto domain_it = config_json.find("domain_list");
        if (domain_it == config_json.end() || !domain_it->is_array())
        {
            LOG_MSG("domain_list invalid");
            return 1;
        }
        for (auto& item : *domain_it)
        {
            if (!item.is_object())
            {
                LOG_MSG("domain_list invalid");
                return 1;
            }

            auto it = item.find("domain");
            if (it == item.end() || !it.value().is_string())
            {
                LOG_MSG("domain_list invalid");
                return 1;
            }
            config::domain_type domain;
            domain.domain = it.value();
            it            = item.find("sub_domain");
            if (it == item.end() || !it.value().is_string())
            {
                LOG_MSG("domain_list invalid");
                return 1;
            }
            domain.sub_domain = it.value();
            domain.ttl        = GetValue(item, "ttl", "600");
            global_config.domain_list.emplace_back(std::move(domain));
        }

        auto query_cmd_it = config_json.find("query_self_cmd");
        if (query_cmd_it != config_json.end() && query_cmd_it->is_string())
        {
            global_config.query_self_info.cmd =
                GetValue(*query_cmd_it,
                         "cmd",
                         "curl -s -X GET -L https://1.1.1.1/cdn-cgi/trace | awk -F '=' '{if (NR==3){print $2}}'");
            global_config.query_self_info.is_cmd = true;
        }

        auto query_req_it = config_json.find("query_self_request");
        if (query_req_it != config_json.end() && query_req_it->is_object())
        {
            std::string method = GetValue(*query_req_it, "method", "GET");
            if (method == "GET")
            {
                global_config.query_self_info.method = config::http_method::kGET;
            }
            else if (method == "POST")
            {
                global_config.query_self_info.method = config::http_method::kPOST;
            }
            else if (method == "PUT")
            {
                global_config.query_self_info.method = config::http_method::kPUT;
            }
            else if (method == "DELETE")
            {
                global_config.query_self_info.method = config::http_method::kDELETE;
            }

            global_config.query_self_info.port   = GetValue(*query_req_it, "port", 443);
            global_config.query_self_info.host   = GetValue(*query_req_it, "host", "ifconfig.me");
            global_config.query_self_info.path   = GetValue(*query_req_it, "path", "/ip");
            global_config.query_self_info.body   = GetValue(*query_req_it, "body", "");
            global_config.query_self_info.is_cmd = false;
        }

        global_config.query_self_info.interval = GetValue(config_json, "interval", 10);

        std::map<std::string, domain_info> domain_info_map;
        get_domain_list(domain_info_map);
        if (domain_info_map.empty())
        {
            return 1;
        }

        update_dns_loop(domain_info_map);
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

static void update_dns_loop(std::map<std::string, domain_info>& domain_info_map)
{
    try
    {
        int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (timer_fd < 0)
        {
            LOG_MSG("timerfd_create failed, errno:%d, desc:%s", errno, strerror(errno));
            _exit(1);
        }
        int flag = fcntl(timer_fd, F_GETFD);
        if (flag == -1)
        {
            LOG_MSG("fcntl failed, errno:%d, desc:%s", errno, strerror(errno));
            _exit(1);
        }
        flag |= FD_CLOEXEC;
        if (fcntl(timer_fd, F_SETFD, flag) == -1)
        {
            LOG_MSG("fcntl failed, errno:%d, desc:%s", errno, strerror(errno));
            _exit(1);
        }

        do_on_exit on_exit([&timer_fd]() {
            if (timer_fd > 0)
            {
                close(timer_fd);
            }
        });

        struct itimerspec its = {};
        memset(&its, 0, sizeof(its));
        its.it_interval.tv_sec = 0;
        its.it_value.tv_sec    = 600;
        if (timerfd_settime(timer_fd, 0, &its, nullptr) != 0)
        {
            LOG_MSG("timerfd_settime failed, errno:%d, desc:%s", errno, strerror(errno));
            return;
        }

        std::string current_ip;
        std::regex ip_reg(R"(((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3})");

        std::atomic_uint64_t loop_times = {0};

        auto main_loop = [&]() {
            struct sigaction sa = {};
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
                    for (const auto& item : global_config.domain_list)
                    {
                        // domain
                        auto it = domain_info_map.find(item.domain);
                        if (it == domain_info_map.end())
                        {
                            LOG_MSG("cann't find domain: %s at dnspod list", item.domain.c_str());
                            exit(1);
                        }

                        // iterator record list
                        // update dns record
                        for (auto& record : it->second.record_info_vec)
                        {
                            // the sub domain must match
                            if (record.id.empty() || record.sub_domain.empty() || record.sub_domain != item.sub_domain
                                || current_ip == record.value)
                            {
                                continue;
                            }

                            // update dns record
                            if (update_dns_record(it->second.domain_id,
                                                  record.id,
                                                  item.sub_domain,
                                                  record.type,
                                                  current_ip,
                                                  item.ttl))
                            {
                                LOG_MSG("update domain: %s to: %s", item.domain.c_str(), current_ip.c_str());
                                record.value = current_ip;
                            }
                        }
                    }
                }
                std::this_thread::sleep_for(std::chrono::seconds(global_config.query_self_info.interval));
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
                union sigval sval = {};
                sval.sival_int    = 0x1234;
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

static bool http_sync_request(const config::http_method method,
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

        httplib::Result resp(nullptr, httplib::Error::Unknown);
        switch (method)
        {
        case config::http_method::kGET:
            resp = cli.Get(path.c_str(), header);
            break;
        case config::http_method::kPUT:
            resp = cli.Put(path.c_str(), header, request, content_type.c_str());
            break;
        case config::http_method::kPOST:
            resp = cli.Post(path.c_str(), header, request, content_type.c_str());
            break;
        case config::http_method::kDELETE:
            resp = cli.Delete(path.c_str(), header);
            break;

        default:
            LOG_MSG("unknown http method");
            return false;
        }

        if (resp)
        {
            resp_str = resp->body;
            return true;
        }
        else
        {
            LOG_MSG("http request failed");
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
        wrap_request_str("login_token", global_config.dnspod_token, request);
        wrap_request_str("format", "json", request);
        wrap_request_str("lang", "cn", request);

        httplib::Headers header;
        header.emplace("User-Agent", agent);
        header.emplace("Host", dnspod_api_host);
        std::string resp;
        http_sync_request(config::http_method::kPOST,
                          dnspod_api_host,
                          443,
                          path,
                          header,
                          "application/x-www-form-urlencoded",
                          request,
                          resp);
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

static std::string execute_command(const std::string& cmd)
{
    auto* f = popen(cmd.c_str(), "r");
    if (f == nullptr)
    {
        return "";
    }

    size_t pos = 0;
    std::string buf;
    while (true)
    {
        if (buf.size() <= pos)
        {
            buf.resize(buf.size() + 256);
        }
        pos += fread(&buf[pos], sizeof(char), buf.size() - pos, f);
        if (feof(f) || ferror(f))
        {
            break;
        }
    }
    fclose(f);
    buf.resize(pos);

    return buf;
}

// trim from start (in place)
static inline void ltrim(std::string& s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
}

// trim from end (in place)
static inline void rtrim(std::string& s)
{
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string& s)
{
    ltrim(s);
    rtrim(s);
}

static std::string get_current_ip()
{
    std::string host_ip;
    if (!global_config.query_self_info.is_cmd)
    {
        http_sync_request(global_config.query_self_info.method,
                          global_config.query_self_info.host,
                          global_config.query_self_info.port,
                          global_config.query_self_info.path,
                          httplib::Headers(),
                          "application/x-www-form-urlencoded",
                          global_config.query_self_info.body,
                          host_ip);
    }
    else
    {
        host_ip = execute_command(global_config.query_self_info.cmd);
        trim(host_ip);
    }
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
                        record.id         = GetValue(item, "id", "");
                        record.sub_domain = GetValue(item, "name", "");  //@, www,
                        record.type       = GetValue(item, "type", "A");  // A, AAAA
                        record.value      = GetValue(item, "value", "");  // IP
                        record.ttl        = GetValue(item, "ttl", "");  // ttl
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

static std::string get_time_str()
{
    std::string time_str;
    try
    {
        constexpr size_t date_fmt_len = 20;
        time_str.resize(date_fmt_len);
        auto now      = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        struct tm tm  = {};
        localtime_r(&t, &tm);
        snprintf(&time_str[0],
                 date_fmt_len,
                 "%04d-%02d-%02d %02d:%02d:%02d",
                 tm.tm_year + 1900,
                 tm.tm_mon,
                 tm.tm_mday,
                 tm.tm_hour,
                 tm.tm_min,
                 tm.tm_sec);
    }
    catch (...)
    {
        time_str.clear();
    }

    return time_str;
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
