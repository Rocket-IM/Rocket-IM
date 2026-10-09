"""设备注册挑战的有界公开编码；不把私钥持有证明当作联系人核验。"""

from contract import ProtocolError, decode_bytes, fields, parse_json, parse_u64, validate_id

PROTOCOL_VERSION = "rim-device-registration-1"
PURPOSE = "register_device"
TTL_MS = 300000
MAX_CHALLENGE_BYTES = 4096
OPERATIONS = {"begin_device_registration", "complete_device_registration"}


def invalid():
    raise ProtocolError("registration_invalid", "设备注册材料格式或范围无效")


def challenge(encoded):
    try:
        value = parse_json(decode_bytes(encoded, "challenge_bytes", MAX_CHALLENGE_BYTES))
        fields(value, ("protocol_version", "service_id", "account_id", "device_id", "registration_id",
                       "signature_key", "purpose", "challenge_nonce", "issued_at_ms", "expires_at_ms"))
        if value["protocol_version"] != PROTOCOL_VERSION or value["purpose"] != PURPOSE:
            invalid()
        for name in ("service_id", "account_id", "device_id", "registration_id"):
            validate_id(value[name], name)
        for name in ("signature_key", "challenge_nonce"):
            if len(decode_bytes(value[name], name, 32)) != 32:
                invalid()
        issued = parse_u64(value["issued_at_ms"], "issued_at_ms")
        expires = parse_u64(value["expires_at_ms"], "expires_at_ms")
        if not 0 < expires - issued <= TTL_MS:
            invalid()
        return value
    except ProtocolError:
        invalid()


def proof(value):
    try:
        fields(value, ("statement_bytes", "signature_bytes"))
        statement = challenge(value["statement_bytes"])
        if len(decode_bytes(value["signature_bytes"], "signature_bytes", 64)) != 64:
            invalid()
        return statement
    except ProtocolError:
        invalid()


def validate_request(operation, value):
    try:
        if operation == "begin_device_registration":
            fields(value, ("service_id", "registration_id", "signature_key"))
            validate_id(value["registration_id"], "registration_id")
            if len(decode_bytes(value["signature_key"], "signature_key", 32)) != 32:
                invalid()
        elif operation == "complete_device_registration":
            fields(value, ("service_id", "proof"))
            proof(value["proof"])
        else:
            invalid()
        validate_id(value["service_id"], "service_id")
        return value
    except ProtocolError:
        invalid()


def registered(statement):
    return {"status": "registered", **{name: statement[name] for name in
            ("service_id", "account_id", "device_id", "registration_id", "signature_key")}}
