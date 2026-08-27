from secure_rag.authz.client import SpiceDBSimulator, get_authz_client, reset_authz_client

RealSpiceDBClient = None


def get_spicedb_client():
    return get_authz_client()
