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

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>

#include <nlohmann/json.hpp>

struct do_on_exit
{
    do_on_exit(std::function<void(void)> hd) : do_on_exit_hd_(hd) {}
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

struct record_info
{
    uint32_t record_id = 0;
    std::string record_name;
    std::string record_type;
    std::string record_value;
    std::string enabled;
    inline bool operator<(const record_info &other) const
    {
        return record_id < other.record_id || record_value < other.record_value;
    }
};

struct domain_info
{
    uint32_t domain_id = 0;
    uint32_t records = 0;
    std::string domain;
    std::set<record_info> record_info_vec;
};

static bool http_sync_request(const boost::beast::http::verb method,
                              const std::string &host,
                              const std::string &port = "443",
                              const std::string &path = "/",
                              const std::string &request = "",
                              const std::map<boost::beast::http::field, std::string> &header = std::map<boost::beast::http::field, std::string>(),
                              std::string *resp = nullptr);

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "the config path must set\n");
        return 1;
    }

    try
    {
        std::ifstream ifs(argv[1]);
        if (!ifs)
        {
            fprintf(stderr, "open config: %s failed\n", argv[1]);
            return 1;
        }

        nlohmann::json config_json;
        ifs >> config_json;
        
        std::map<std::string, domain_info> domain_info_map;
    }
    catch(const std::exception &err)
    {

    }
}

bool http_sync_request(const boost::beast::http::verb method,
                       const std::string &host,
                       const std::string &port,
                       const std::string &path,
                       const std::string &request,
                       const std::map<boost::beast::http::field, std::string> &header,
                       std::string *resp)
{
    namespace beast = boost::beast; // from <boost/beast.hpp>
    namespace http = beast::http;   // from <boost/beast/http.hpp>
    namespace net = boost::asio;    // from <boost/asio.hpp>
    namespace ssl = net::ssl;       // from <boost/asio/ssl.hpp>
    using tcp = net::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

    try
    {
        ssl::context ctx(ssl::context::tls_client);
        ctx.set_default_verify_paths();
        ctx.set_verify_mode(ssl::verify_peer);

        net::io_context ioc;
        tcp::resolver resolver(ioc);
        beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

        if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()))
        {
            beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
            throw beast::system_error{ec};
        }

        auto const results = resolver.resolve(host, port);
        beast::get_lowest_layer(stream).connect(results);
        stream.handshake(ssl::stream_base::client);
        http::request<http::string_body> req{method, path, 11, request};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        for (auto &item : header)
        {
            req.set(item.first, item.second);
        }

        http::write(stream, req);
        beast::flat_buffer buffer;

        http::response<http::string_body> res;
        http::read(stream, buffer, res);
        if (resp)
        {
            *resp = res.body();
        }

        beast::error_code ec;
        stream.shutdown(ec);
        if (ec == net::error::eof)
        {
            ec = {};
        }

        if (ec)
        {
            throw beast::system_error{ec};
        }
    }
    catch (const std::exception &err)
    {
        return false;
    }

    return true;
}