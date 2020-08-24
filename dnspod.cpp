#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <cstdlib>
#include <iostream>
#include <string>

#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>

class file_helper
{
private:
    /* data */
public:
    file_helper() = default;
    ~file_helper();

    bool open(const std::string &file_name, const int mode);

    bool read(std::string &data);

    bool read(std::string &data, const std::size_t file_Size);

    bool write(const std::string &data);

    bool write_truncate_atomic(const std::string &data);

    int fd() const 
    {
        return fd_;
    }

    const std::string& file_name() const
    {
        return file_name_;
    }

private:
    int fd_ = -1;
    std::string file_name_;
};

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

static bool http_sync_request(const std::string &host,
                              const std::string &port = "443",
                              const std::string &path = "/",
                              std::string *resp = nullptr);

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        
    }
}

bool http_sync_request(const std::string &host,
                       const std::string &port,
                       const std::string &path,
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
        http::request<http::string_body> req{http::verb::get, path, 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
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