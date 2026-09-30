"""CLI.

    sudo python3 -m control_plane serve [--config cfg.json]
    sudo python3 -m control_plane image import NAME DOCKER_REF
    sudo python3 -m control_plane create IMAGE
    sudo python3 -m control_plane fork SANDBOX_ID
    sudo python3 -m control_plane exec SANDBOX_ID -- CMD...
    sudo python3 -m control_plane info|destroy SANDBOX_ID
    sudo python3 -m control_plane list|images

Everything except ``serve`` talks to a running server over its socket.
"""
from __future__ import annotations

import argparse
import json
import sys

from .client import Client
from .config import Config


def main(argv=None):
    ap = argparse.ArgumentParser(prog="control_plane")
    ap.add_argument("--config")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve")
    img = sub.add_parser("image")
    img.add_argument("action", choices=["import"])
    img.add_argument("name")
    img.add_argument("docker_ref")
    sub.add_parser("create").add_argument("image")
    for name in ("fork", "info", "destroy"):
        sub.add_parser(name).add_argument("sandbox_id")
    ex = sub.add_parser("exec")
    ex.add_argument("sandbox_id")
    ex.add_argument("--timeout", type=float)
    ex.add_argument("argv", nargs=argparse.REMAINDER)
    sub.add_parser("list")
    sub.add_parser("images")
    args = ap.parse_args(argv)
    cfg = Config.load(args.config)

    if args.cmd == "serve":
        from .sandbox import Manager
        from .server import Server
        mgr = Manager(cfg)
        server = Server(mgr)  # socket is bound before we announce readiness
        print(json.dumps({"reconcile": mgr.last_reconcile, "socket": cfg.socket_path,
                          "dev_mode": cfg.dev_mode, "storage": cfg.storage,
                          "cgroup_enforced": mgr.cg.enforced}), flush=True)
        server.serve_forever()
        return 0

    c = Client(cfg.socket_path)
    if args.cmd == "image":
        res = c.call("import_image", name=args.name, docker_ref=args.docker_ref)
    elif args.cmd == "create":
        res = c.create_environment(args.image)
    elif args.cmd == "fork":
        res = c.fork(args.sandbox_id)
    elif args.cmd == "info":
        res = c.snapshot_info(args.sandbox_id)
    elif args.cmd == "destroy":
        res = c.destroy(args.sandbox_id)
    elif args.cmd == "list":
        res = c.list_sandboxes()
    elif args.cmd == "images":
        res = c.call("list_images")
    else:  # exec
        argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        kw = {"timeout": args.timeout} if args.timeout else {}
        res = c.exec(args.sandbox_id, argv, **kw)
        sys.stdout.write(res["stdout"])
        sys.stderr.write(res["stderr"])
        return res["exit_code"] if not res["timed_out"] else 124
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
