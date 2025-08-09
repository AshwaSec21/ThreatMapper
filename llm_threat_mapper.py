import re

# ... other imports/utilities in your module stay as-is ...


def _normalize(s):
    return (s or "").strip().lower()


def _split_before_colon(text):
    """
    Return the left side before the first colon and the full text.
    E.g., "Firewall to NTP: request" -> ("Firewall to NTP", "Firewall to NTP: request")
    """
    if not text:
        return "", ""
    parts = text.split(":", 1)
    if len(parts) == 2:
        return parts[0].strip(), text
    return "", text


def _match_assets_in_text(text, asset_list):
    """
    Case-insensitive containment check of known assets inside text.
    Returns unique matched asset names as they appear in asset_list (original casing).
    """
    if not text or not asset_list:
        return []
    txt = _normalize(text)
    hits = []
    for a in asset_list:
        if not a:
            continue
        if _normalize(a) in txt:
            hits.append(a)
    # preserve input order uniqueness
    seen = set()
    out = []
    for a in hits:
        if a not in seen:
            out.append(a)
            seen.add(a)
    return out


def get_threat_assets(interaction, asset_list, description=None):
    """
    Extract involved assets for a threat.
    Strategy:
      1) Try "prefix before colon" from Interaction (e.g., "Firewall to NTP: ...") and split by common separators.
      2) If none found, scan Interaction FULL text against asset_list.
      3) If still none and 'description' provided, scan Description full text.

    Returns: list[str] of matched assets (unique, original casing from asset_list).
    """
    assets = []

    # 1) Parse "before colon" pattern (preferred for MS TMT exports)
    left, _ = _split_before_colon(interaction or "")
    if left:
        # split by common separators
        candidates = re.split(r"\bto\b|,|;|/|\\|\|", left, flags=re.IGNORECASE)
        for c in candidates:
            cand = c.strip()
            if cand:
                # exact containment match against asset_list
                for a in asset_list or []:
                    if _normalize(a) == _normalize(cand) or _normalize(a) in _normalize(cand):
                        assets.append(a)

    # 2) Fallback: scan full Interaction
    if not assets:
        assets = _match_assets_in_text(interaction, asset_list)

    # 3) Fallback: scan Description as well
    if not assets and description:
        assets = _match_assets_in_text(description, asset_list)

    # Uniq, preserve order
    seen = set()
    uniq = []
    for a in assets:
        if a not in seen:
            uniq.append(a)
            seen.add(a)
    return uniq
