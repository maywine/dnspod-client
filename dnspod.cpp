#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <cstdlib>
#include <iostream>
#include <string>
#include <map>
#include <set>
#include <fstream>
#include <thread>
#include <chrono>
#include <regex>

#include <nlohmann/json.hpp>

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif

#include <http/httplib.h>

static std::string get_current_time();

#define LOG_MSG(fmt, args...) fprintf(stderr, "%s: " fmt "\n", get_current_time().c_str(), ## args)

enum http_method
{
    kGET = 0,
    kPUT,
    kPOST,
    kDELETE
};

struct record_info
{
    std::string record_id;
    std::string record_sub_domain;
    std::string record_type;
    std::string record_value;
    std::string ttl;
    inline bool operator<(const record_info &other) const
    {
        return record_id < other.record_id || record_sub_domain < other.record_sub_domain || record_type < other.record_type || record_value < other.record_value;
    }
};

struct domain_info
{
    std::string domain_id;
    std::string domain;
    std::set<record_info> record_info_set;
    std::vector<record_info> record_info_vec;
};

static std::string GetValue(const nlohmann::json &js,
                            const std::string &key,
                            const char *default_value);
                        
static void wrap_request_str(const std::string &key,
                             const std::string &value,
                             std::string &req_str);

static bool http_sync_request(const http_method method,
                              const std::string &host,
                              const uint16_t port,
                              const std::string &path,
                              const httplib::Headers &header,
                              const std::string &content_type,
                              const std::string &request,
                              std::string &resp_str);

static bool dnspod_api(const std::string &path,
                       const std::string &request,
                       nlohmann::json &resp_js);

static std::string get_current_ip();

static void get_domain_list(std::map<std::string, domain_info> &domain_info_map);

static bool update_dns_record(const std::string &domain_id,
                              const std::string &record_id,
                              const std::string &sub_domain,
                              const std::string &record_type,
                              const std::string &ip,
                              const std::string &ttl);

static void update_dns_loop(const nlohmann::json &domain_list_js,
                            std::map<std::string, domain_info> &domain_info_map);

static std::string s_g_dnspod_token = "";

int main(int argc, char **argv)
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

        nlohmann::json config_json;
        ifs >> config_json;

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

        std::map<std::string, domain_info> domain_info_map;
        get_domain_list(domain_info_map);
        if (domain_info_map.empty())
        {
            return 1;
        }

        update_dns_loop(*domain_it, domain_info_map);
    }
    catch (const std::exception &err)
    {
        LOG_MSG("main, catch exception:%s", err.what());
        return 1;
    }
}

static void update_dns_loop(const nlohmann::json &domain_list_js, std::map<std::string, domain_info> &domain_info_map)
{
    try
    {
        uint64_t count = 0;
        std::string current_ip;
        std::regex ip_reg("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}");

        while (true)
        {
            if (count % (15 * 60 / 5) == 0) // 15 mim get ip from dnspod
            {
                domain_info_map.clear();
                while (true)
                {
                    get_domain_list(domain_info_map);
                    if (domain_info_map.empty())
                    {
                        LOG_MSG("try domain list failed");
                        std::this_thread::sleep_for(std::chrono::seconds(10));
                        continue;
                    }

                    for (auto &item : domain_info_map)
                    {
                        item.second.record_info_vec.reserve(item.second.record_info_set.size());
                        std::copy(item.second.record_info_set.begin(), item.second.record_info_set.end(), std::back_inserter(item.second.record_info_vec));
                    }

                    break;
                }
            }

            current_ip = get_current_ip();
            if (std::regex_match(current_ip, ip_reg))
            {
                for (auto &item : domain_list_js)
                {
                    if (!item.is_object())
                    {
                        LOG_MSG("invalid domain_list: %s", domain_list_js.dump().c_str());
                        exit(1);
                    }

                    auto domain = GetValue(item, "domain", "");
                    auto sub_domain = GetValue(item, "sub_domain", "");
                    if (domain.empty() || sub_domain.empty())
                    {
                        LOG_MSG("invalid domain_list: %s", domain_list_js.dump().c_str());
                        exit(1);
                    }
                    auto ttl = GetValue(item, "ttl", "600");

                    auto it = domain_info_map.find(domain);
                    if (it == domain_info_map.end())
                    {
                        LOG_MSG("cann't find domain: %s at dnspod list", domain.c_str());
                        exit(1);
                    }

                    // update dns record
                    for (auto &record : it->second.record_info_vec)
                    {
                        if (record.record_id.empty() || record.record_sub_domain.empty())
                        {
                            continue;
                        }

                        // Last IP is the same as current IP
                        if (current_ip == record.record_value)
                        {
                            continue;
                        }

                        //update dns record
                        if (update_dns_record(it->second.domain_id, record.record_id, sub_domain, record.record_type, current_ip, ttl))
                        {
                            LOG_MSG("update domain: %s to: s%", domain.c_str(), current_ip.c_str());
                            record.record_value = current_ip;
                        }
                    }
                }
            }

            ++count;
            std::this_thread::sleep_for(std::chrono::seconds(15));
        }
    }
    catch (const std::exception &err)
    {
    }
}

static std::string GetValue(const nlohmann::json &js, const std::string &key, const char *default_value)
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
                              const std::string &host,
                              const uint16_t port,
                              const std::string &path,
                              const httplib::Headers &header,
                              const std::string &content_type,
                              const std::string &request,
                              std::string &resp_str)
{
    try
    {
        httplib::SSLClient cli(host, port);
        cli.enable_server_certificate_verification(true);
        httplib::Result resp(nullptr, httplib::Error::Unknown);
        switch (method)
        {
        case http_method::kGET :
            resp = cli.Get(path.c_str(), header);
            break;
        case http_method::kPUT :
            resp = cli.Put(path.c_str(), header, request, content_type.c_str());
            break;
        case http_method::kPOST :
            resp = cli.Post(path.c_str(), header, request, content_type.c_str());
            break;
        case http_method::kDELETE :
            resp = cli.Delete(path.c_str(), header);
            break;

        default :
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
    catch (...)
    {
        return false;
    }
}

static bool dnspod_api(const std::string &path,
                       std::string &request,
                       nlohmann::json &resp_js)
{
    try
    {
        static const std::string dnspod_api_host = "dnsapi.cn"; 
        static const std::string agent = "AnripDdns/6.0.0(mail@anrip.com)";
        wrap_request_str("login_token", s_g_dnspod_token, request);
        wrap_request_str("format", "json", request);

        httplib::Headers header;
        header.emplace("User-Agent", agent);
        header.emplace("Host", dnspod_api_host);
        std::string resp;
        http_sync_request(http_method::kPOST, dnspod_api_host, 443, path, header, "application/x-www-form-urlencoded", request, resp);
        resp_js = nlohmann::json::parse(resp);
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
    catch (const std::exception &err)
    {
        LOG_MSG("dnspod_api failed, catch exception:%s", err.what());
        return false;
    }

}

static std::string get_current_ip()
{
    std::string host_ip;
    http_sync_request(http_method::kGET, "ifconfig.me", 443, "/ip", httplib::Headers(), "", "", host_ip);
    return host_ip;
}

static void get_domain_list(std::map<std::string, domain_info> &domain_info_map)
{
    try
    {
        std::string req_str;
        nlohmann::json resp_js;
        if (!dnspod_api("/Domain.List", req_str, resp_js)) //Domain.List
        {
            LOG_MSG("get domain list failed");
            return;
        }

        auto it = resp_js.find("domains");
        if (it != resp_js.end() && it->is_array())
        {
            for (auto &item : *it)
            {
                if (!item.is_object())
                {
                    continue;
                }

                domain_info domain;
                std::string domain_str = GetValue(item, "name", "");
                domain.domain = domain_str;

                domain.domain_id = GetValue(item, "id", "");
                if (domain.domain.empty() || domain.domain_id.empty())
                {
                    continue;
                }

                std::string req_str;
                wrap_request_str("domain_id", domain.domain_id, req_str);
                nlohmann::json resp_js;
                if (!dnspod_api("/Record.List", req_str, resp_js)) //Record.List
                {
                    LOG_MSG("get domain: %s record list failed", domain_str.c_str());
                    continue;
                }

                auto it = resp_js.find("records");
                if (it != resp_js.end() && it->is_array())
                {
                    for (auto &item : *it)
                    {
                        if (!item.is_object())
                        {
                            continue;
                        }

                        record_info record;
                        record.record_id = GetValue(item, "id", "");
                        record.record_sub_domain = GetValue(item, "name", ""); //@, www,
                        record.record_type = GetValue(item, "type", "A");      //A, AAAA
                        record.record_value = GetValue(item, "value", "");     // IP
                        record.ttl = GetValue(item, "ttl", "");                // ttl
                        domain.record_info_set.insert(std::move(record));
                    }
                }

                domain_info_map.emplace(std::move(domain_str), std::move(domain));
            }
        }
    }
    catch (const std::exception &err)
    {
        LOG_MSG("get_domain_list failed, catch exception:%s", err.what());
    }
}

static bool update_dns_record(const std::string &domain_id,
                              const std::string &record_id,
                              const std::string &sub_domain,
                              const std::string &record_type,
                              const std::string &ip,
                              const std::string &ttl)
{
    std::string req_str;
    wrap_request_str("domain_id", domain_id, req_str);
    wrap_request_str("record_id", record_id, req_str);
    wrap_request_str("sub_domain", sub_domain, req_str);
    wrap_request_str("record_type", record_type, req_str);
    wrap_request_str("value", ip, req_str);
    wrap_request_str("ttl", ttl, req_str);
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
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::string tm_str(std::ctime(&t));
        tm_str.pop_back();
        return tm_str;
    }
    catch (...)
    {
        return "";
    }
}

static void wrap_request_str(const std::string &key,
                             const std::string &value,
                             std::string &req_str)
{
    if (!req_str.empty())
    {
        req_str.append("&");
    }
    req_str.append(key);
    req_str.append("=");
    req_str.append(value);
}
