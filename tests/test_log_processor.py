from src.log_processor import parse_log_line, process_entry, should_skip


def test_parse_valid_json(sample_json_line):
    entry = parse_log_line(sample_json_line)
    assert entry is not None
    assert entry.remote_addr == "93.184.216.34"
    assert entry.status == 200
    assert entry.request_method == "GET"
    assert entry.request_uri == "/index.html"


def test_parse_invalid_json():
    assert parse_log_line("not json at all") is None
    assert parse_log_line("") is None
    assert parse_log_line("   ") is None


def test_parse_combined_format_returns_none():
    line = '172.18.0.1 - - [06/Apr/2026:13:04:02 +0000] "GET / HTTP/1.1" 200 5988 "-" "curl"'
    assert parse_log_line(line) is None


def test_skip_internal_ip(sample_internal_line):
    entry = parse_log_line(sample_internal_line)
    assert entry is not None
    assert should_skip(entry) is True


def test_skip_static_asset(sample_static_line):
    entry = parse_log_line(sample_static_line)
    assert entry is not None
    assert should_skip(entry) is True


def test_allow_normal_request(sample_json_line):
    entry = parse_log_line(sample_json_line)
    assert entry is not None
    assert should_skip(entry) is False


def test_skip_health_check():
    line = (
        '{"time":"2026-04-06T13:07:00+00:00","remote_addr":"8.8.8.8",'
        '"request":"GET / HTTP/1.1","status":200,"body_bytes_sent":100,'
        '"http_referer":"","http_user_agent":"Uptime-Kuma/1.0","request_time":0.000,'
        '"ssl_protocol":"","request_method":"GET","request_uri":"/"}'
    )
    entry = parse_log_line(line)
    assert entry is not None
    assert should_skip(entry) is True


def test_process_entry_recovers_http_request_when_fields_missing():
    line = (
        '{"time":"2026-04-07T12:31:28+00:00","remote_addr":"198.51.100.144",'
        '"request":"GET /aaa9 HTTP/1.1","status":301,"body_bytes_sent":162,'
        '"http_referer":"","http_user_agent":"Mozilla/5.0","request_time":0.000,'
        '"ssl_protocol":"","request_method":"","request_uri":""}'
    )
    entry = parse_log_line(line)
    assert entry is not None
    visit = process_entry(entry)
    assert visit["method"] == "GET"
    assert visit["path"] == "/aaa9"


def test_process_entry_marks_tls_handshake_on_http_port():
    line = (
        '{"time":"2026-04-07T12:31:28+00:00","remote_addr":"198.51.100.144",'
        '"request":"\\u0016\\u0003\\u0001\\u0005ab","status":400,"body_bytes_sent":150,'
        '"http_referer":"","http_user_agent":"","request_time":0.021,'
        '"ssl_protocol":"","request_method":"","request_uri":""}'
    )
    entry = parse_log_line(line)
    assert entry is not None
    visit = process_entry(entry)
    assert visit["method"] == "TLS"
    assert visit["path"] == "[handshake on HTTP port]"
