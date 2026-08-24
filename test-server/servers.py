#!/usr/bin/env python3
"""Configurable OPC UA test server for the opcua-discover NSE script.

One process serves one configuration; docker-compose starts several of them so
the NSE script can be exercised against every case it claims to detect:

  insecure   SecurityPolicy None only, anonymous - the common misconfiguration
  secure     every modern policy, valid certificate, username authentication
  legacy     deprecated SHA-1 policies with a 1024 bit SHA-1 certificate
  expired    a valid policy set carried by an expired certificate
  shared-a   two servers presenting the same certificate, for the
  shared-b   cross-host fingerprint correlation

Run directly:  python servers.py --mode secure --port 4841
"""

import argparse
import asyncio
import logging
import pathlib

from asyncua import Server, ua
from asyncua.common.methods import uamethod

CERTS = pathlib.Path(__file__).parent / "certs"

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("opcua-test")


def policies(*names):
    """Resolve SecurityPolicyType names, skipping ones this asyncua lacks."""
    out = []
    for name in names:
        policy = getattr(ua.SecurityPolicyType, name, None)
        if policy is None:
            logger.warning("SecurityPolicyType.%s not available in this asyncua", name)
        else:
            out.append(policy)
    return out


MODES = {
    "insecure": {
        "app_uri": "urn:opcua-nse:test:insecure",
        "name": "OPC UA Test Server (insecure)",
        "cert": None,
        "policies": ("NoSecurity",),
        "users": True,
        # Anonymous sessions get full read access: the misconfiguration the
        # discover and browse scripts are meant to surface.
        "anonymous_role": "user",
    },
    "secure": {
        "app_uri": "urn:opcua-nse:test:secure",
        "name": "OPC UA Test Server (secure)",
        "cert": "server_ok",
        "policies": (
            "NoSecurity",
            "Basic256Sha256_Sign",
            "Basic256Sha256_SignAndEncrypt",
            "Aes128Sha256RsaOaep_Sign",
            "Aes128Sha256RsaOaep_SignAndEncrypt",
            "Aes256Sha256RsaPss_Sign",
            "Aes256Sha256RsaPss_SignAndEncrypt",
        ),
        "users": True,
        "anonymous_role": "user",
    },
    "legacy": {
        "app_uri": "urn:opcua-nse:test:legacy",
        "name": "OPC UA Test Server (legacy crypto)",
        "cert": "server_weak",
        "policies": (
            "NoSecurity",
            "Basic128Rsa15_Sign",
            "Basic128Rsa15_SignAndEncrypt",
            "Basic256_Sign",
            "Basic256_SignAndEncrypt",
        ),
        "users": True,
        "anonymous_role": "user",
    },
    "expired": {
        "app_uri": "urn:opcua-nse:test:expired",
        "name": "OPC UA Test Server (expired certificate)",
        "cert": "server_expired",
        "policies": ("NoSecurity", "Basic256Sha256_SignAndEncrypt"),
        "users": False,
        # Denies reads to anonymous sessions, so the scripts have to report
        # that case instead of silently returning nothing.
        "anonymous_role": "anonymous",
    },
    "shared-a": {
        "app_uri": "urn:opcua-nse:test:shared",
        "name": "OPC UA Test Server (shared certificate A)",
        "cert": "server_shared",
        "policies": ("NoSecurity", "Basic256Sha256_SignAndEncrypt"),
        "users": False,
        "anonymous_role": "user",
    },
    "shared-b": {
        "app_uri": "urn:opcua-nse:test:shared",
        "name": "OPC UA Test Server (shared certificate B)",
        "cert": "server_shared",
        "policies": ("NoSecurity", "Basic256Sha256_SignAndEncrypt"),
        "users": False,
        "anonymous_role": "user",
    },
}

# Credentials the opcua-brute script is expected to find.
VALID_USERS = {"operator": "operator", "engineer": "Password1"}


def build_user_manager(anonymous_role="user"):
    """A user manager that accepts VALID_USERS, so brute forcing is testable.

    anonymous_role decides what an anonymous session may do: "user" grants the
    same read access a named user gets, "anonymous" leaves the session with the
    restricted default role that asyncua denies reads to.
    """
    UserManager = User = UserRole = None
    for module in ("asyncua.server.user_managers", "asyncua.server.users",
                   "asyncua.server.internal_server"):
        try:
            mod = __import__(module, fromlist=["UserManager", "User", "UserRole"])
        except ImportError:
            continue
        UserManager = getattr(mod, "UserManager", UserManager)
        User = getattr(mod, "User", User)
        UserRole = getattr(mod, "UserRole", UserRole)

    if not (UserManager and User and UserRole):
        logger.warning("this asyncua has no pluggable user manager; "
                       "every credential will be accepted")
        return None

    anonymous = User(role=UserRole.User) if anonymous_role == "user" \
        else User(role=UserRole.Anonymous)

    class TestUserManager(UserManager):
        def get_user(self, iserver, username=None, password=None, certificate=None):
            if username is None:
                return anonymous
            if VALID_USERS.get(username) == password:
                logger.info("accepted login for %s", username)
                return User(role=UserRole.User)
            logger.info("rejected login for %s", username)
            return None

    return TestUserManager()


@uamethod
def multiply(_parent, x, y):
    return x * y


async def build_address_space(server, idx):
    """A small plant-like address space with read-only and writable nodes."""
    objects = server.nodes.objects
    folder = await objects.add_folder(idx, "Plant")

    temperature = await folder.add_variable(idx, "Temperature", 20.5)
    await temperature.set_writable()          # anonymous write - a finding
    pressure = await folder.add_variable(idx, "Pressure", 101.3)
    await pressure.set_writable()
    setpoint = await folder.add_variable(idx, "Setpoint", 21.0)
    await setpoint.set_writable()
    serial = await folder.add_variable(idx, "SerialNumber", "SN-000042")
    # serial stays read-only

    await temperature.add_property(idx, "EngineeringUnit", "Celsius")
    await objects.add_method(idx, "Multiply", multiply,
                             [ua.VariantType.Int64, ua.VariantType.Int64],
                             [ua.VariantType.Int64])


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=sorted(MODES), default="insecure")
    parser.add_argument("--port", type=int, default=4840)
    parser.add_argument("--path", default="/nse/")
    args = parser.parse_args()

    config = MODES[args.mode]
    server = Server(user_manager=build_user_manager(
        config.get("anonymous_role", "user")))
    await server.init()

    endpoint = f"opc.tcp://0.0.0.0:{args.port}{args.path}"
    server.set_endpoint(endpoint)
    server.set_server_name(config["name"])
    await server.set_application_uri(config["app_uri"])

    if config["cert"]:
        cert = CERTS / f"{config['cert']}_cert.pem"
        key = CERTS / f"{config['cert']}_key.pem"
        if not cert.exists():
            raise SystemExit(f"missing {cert}; run gen_certs.py first")
        await server.load_certificate(str(cert))
        await server.load_private_key(str(key))

    selected = policies(*config["policies"])
    if selected:
        server.set_security_policy(selected)

    # asyncua 1.x takes names, asyncua 2.x takes token classes.
    if hasattr(server, "set_identity_tokens"):
        tokens = [ua.AnonymousIdentityToken]
        if config["users"]:
            tokens.append(ua.UserNameIdentityToken)
        server.set_identity_tokens(tokens)
        token_names = [t.__name__ for t in tokens]
    else:
        token_names = ["Anonymous"] + (["Username"] if config["users"] else [])
        server.set_security_IDs(token_names)

    idx = await server.register_namespace("http://opcua-nse.test/plant")
    await build_address_space(server, idx)

    logger.info("mode=%s endpoint=%s uri=%s cert=%s policies=%d tokens=%s "
                "anonymous_role=%s",
                args.mode, endpoint, config["app_uri"], config["cert"],
                len(selected), ",".join(token_names),
                config.get("anonymous_role", "user"))

    async with server:
        while True:
            await asyncio.sleep(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("stopped")
