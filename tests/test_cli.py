from idps.cli import _parse_ports, build_parser, main


def test_parse_ports_range():
    assert _parse_ports("20-25") == [20, 21, 22, 23, 24, 25]


def test_parse_ports_list():
    assert _parse_ports("22,80,443") == [22, 80, 443]


def test_demo_and_live_are_mutually_exclusive():
    parser = build_parser()
    try:
        parser.parse_args(["--demo", "--live"])
        assert False, "expected SystemExit"
    except SystemExit:
        pass


def test_live_mode_without_required_args_exits():
    try:
        main(["--live"])
        assert False, "expected SystemExit"
    except SystemExit:
        pass
