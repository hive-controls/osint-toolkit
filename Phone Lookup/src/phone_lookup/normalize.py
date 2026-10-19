from __future__ import annotations

from typing import Any

import phonenumbers
from phonenumbers import PhoneNumberFormat, NumberParseException, PhoneNumberType
from phonenumbers import carrier as phone_carrier
from phonenumbers import geocoder as phone_geocoder

TYPE_NAMES = {
    PhoneNumberType.FIXED_LINE: "fixed_line",
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
    PhoneNumberType.TOLL_FREE: "toll_free",
    PhoneNumberType.PREMIUM_RATE: "premium_rate",
    PhoneNumberType.SHARED_COST: "shared_cost",
    PhoneNumberType.VOIP: "voip",
    PhoneNumberType.PERSONAL_NUMBER: "personal_number",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "uan",
    PhoneNumberType.VOICEMAIL: "voicemail",
    PhoneNumberType.UNKNOWN: "unknown",
}


class PhoneParseError(ValueError):
    pass


def parse_number(raw: str, region: str | None = None) -> phonenumbers.PhoneNumber:
    text = (raw or "").strip()
    if not text:
        raise PhoneParseError("empty phone number")
    default_region = (region or "").strip().upper() or None
    if not text.startswith("+") and not default_region:
        raise PhoneParseError(
            "national numbers need --region XX (ISO country), or pass E.164 starting with +"
        )
    try:
        parsed = phonenumbers.parse(text, default_region)
    except NumberParseException as exc:
        raise PhoneParseError(str(exc)) from exc
    return parsed


def describe(parsed: phonenumbers.PhoneNumber) -> dict[str, Any]:
    ntype = phonenumbers.number_type(parsed)
    return {
        "source": "phonenumbers",
        "valid": phonenumbers.is_valid_number(parsed),
        "possible": phonenumbers.is_possible_number(parsed),
        "e164": phonenumbers.format_number(parsed, PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL),
        "digits": phonenumbers.format_number(parsed, PhoneNumberFormat.E164).lstrip("+"),
        "country_code": parsed.country_code,
        "region": phonenumbers.region_code_for_number(parsed),
        "location": phone_geocoder.description_for_number(parsed, "en") or None,
        "carrier_prefix": phone_carrier.name_for_number(parsed, "en") or None,
        "line_type": TYPE_NAMES.get(ntype, "unknown"),
        "note": (
            "carrier_prefix is numbering-plan / original issuer, not the ported live network"
        ),
    }
