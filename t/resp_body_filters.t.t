use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: boron filter
This is just a simple demonstration of the
boron directive provided by ngx_http_boron_filter_module.
--- config
server{
    listen       80;
    server_name  localhost;
    location = /test {
        proxy_pass http://localhost:8000/test.html;
        boron on;
    }
}
--- request
GET /test
--- response_body
<head>this is a paragraph page</head>

--- error_code: 200
