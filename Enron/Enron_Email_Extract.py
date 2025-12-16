# data_extract.py
import os
import sys
import csv
import json
import argparse
import hashlib
import email
import email.policy
import email.utils
from html import unescape
import re

# Heuristic term lists to bias toward financial/technical content
FIN_TERMS = {
    "revenue","revenues","expense","expenses","opex","capex","capital","equity","debt","bond","bonds",
    "hedge","hedging","derivative","derivatives","swap","swaps","futures","forward","options","option",
    "notional","mark-to-market","mtm","pnl","p&l","profit","loss","cashflow","cash flow","liquidity",
    "credit","counterparty","counterparties","exposure","risk","value-at-risk","var","leverage",
    "asset","assets","liability","liabilities","balance sheet","income statement","earnings","guidance",
    "forecast","budget","audit","auditor","audited","compliance","sox","sarbanes","regulation","sec",
    "10-k","10k","10q","10-q","8-k","filing","filings","reporting","dividend","yield","valuation","discount",
    "npv","irr","wacc","write-down","impairment","merger","acquisition","m&a","deal","term sheet",
    "project finance","trade","trading","settlement","clearing","collateral","margin","interest",
    "rate","rates","floating","fixed","pricing","price","market","volatility","vol","basis","spread",
    "swaption","curve","treasury","benchmark","index","indices","loan","syndicated","facility","covenant",
    "megawatt","mw","mwh","gas","pipeline","capacity","transmission","iso","ercot","pjm","bilateral",
    "schedule","nominations","dispatch","generation","outage","contract","term","strip",
    "settle","settlement","delivery","hub","day-ahead","real-time","mark","storage","inventory",
    "tariff","rate case","utility","ppa","ppa's","power purchase agreement"
}

TECH_TERMS = {
    "model","models","modeling","simulation","optimize","optimization","algorithm","algorithms",
    "database","schema","etl","pipeline","batch","realtime","api","query","queries","sql","oracle",
    "sap","system","systems","architecture","latency","bandwidth","encryption","ssl","tls","hash",
    "server","client","deployment","version","config","configuration","script","automation","spark",
    "hadoop","kafka","cluster","node","container","docker","kubernetes","microservice","monitoring",
    "rollback","backup","restore","integration","interface","protocol","sso","ldap"
}

def html_to_text(html: str) -> str:
    if not html:
        return ""
    text = unescape(html)
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", text)
    text = re.sub(r"(?is)<br\s*/?>", "\n", text)
    text = re.sub(r"(?is)</p\s*>", "\n\n", text)
    text = re.sub(r"(?is)<.*?>", "", text)
    text = re.sub(r"\r\n|\r|\n", "\n", text)
    text = re.sub(r"[ \t\f\v]+", " ", text)
    return text.strip()

def extract_addrs(raw):
    if not raw:
        return []
    addrs = email.utils.getaddresses([raw])
    out = []
    for name, addr in addrs:
        name = name.strip() if name else ""
        addr = addr.strip() if addr else ""
        if name and addr:
            out.append(f"{name} <{addr}>")
        elif addr:
            out.append(addr)
        elif name:
            out.append(name)
    # dedupe preserving order
    seen = set()
    uniq = []
    for a in out:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return uniq

def get_best_bodies(msg):
    text_parts = []
    html_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                continue
            ctype = part.get_content_type()
            try:
                payload = part.get_content()
            except Exception:
                try:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, (bytes, bytearray)):
                        payload = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    payload = ""
            if ctype == "text/plain" and isinstance(payload, str):
                text_parts.append(payload)
            elif ctype == "text/html" and isinstance(payload, str):
                html_parts.append(payload)
    else:
        try:
            payload = msg.get_content()
        except Exception:
            try:
                payload = msg.get_payload(decode=True)
                if isinstance(payload, (bytes, bytearray)):
                    payload = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
            except Exception:
                payload = ""
        ctype = msg.get_content_type()
        if ctype == "text/plain" and isinstance(payload, str):
            text_parts.append(payload)
        elif ctype == "text/html" and isinstance(payload, str):
            html_parts.append(payload)
    body_text = "\n\n".join(p.strip() for p in text_parts if p and p.strip())
    body_html = "\n\n".join(p.strip() for p in html_parts if p and p.strip())
    if not body_text and body_html:
        body_text = html_to_text(body_html)
    return body_text, body_html

def parse_date_iso(raw_date):
    if not raw_date:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(raw_date)
        return dt.isoformat()
    except Exception:
        return None

def word_count(text: str) -> int:
    if not text:
        return 0
    return len(re.findall(r"\b\w+\b", text))

def _term_present(text_lower: str, term: str) -> bool:
    if " " in term or "-" in term or "/" in term:
        return term in text_lower
    return re.search(r"\b" + re.escape(term) + r"\b", text_lower) is not None

def fin_tech_hits(text: str):
    if not text:
        return 0, 0
    t = text.lower()
    fin_hits = sum(1 for term in FIN_TERMS if _term_present(t, term))
    tech_hits = sum(1 for term in TECH_TERMS if _term_present(t, term))
    return fin_hits, tech_hits

def fintech_score(text: str) -> int:
    if not text:
        return 0
    t = text.lower()
    fin_hits, tech_hits = fin_tech_hits(t)
    numeric_boost = min(5, len(re.findall(r"\$\s*\d|\b\d{2,}\b", t)))
    return fin_hits * 3 + tech_hits + numeric_boost

def content_hash(text: str) -> str:
    h = hashlib.sha1()
    h.update((text or "").encode("utf-8", errors="replace"))
    return h.hexdigest()

def parse_email_file(path):
    try:
        size = os.path.getsize(path)
    except Exception:
        size = None
    with open(path, "rb") as f:
        data = f.read()
    try:
        msg = email.message_from_bytes(data, policy=email.policy.default)
    except Exception:
        msg = email.message_from_bytes(data, policy=email.policy.compat32)

    subject = (msg.get("Subject") or "").strip()
    from_raw = (msg.get("From") or "").strip()
    to_raw = (msg.get("To") or "").strip()
    cc_raw = (msg.get("Cc") or "").strip()
    bcc_raw = (msg.get("Bcc") or "").strip()
    date_raw = (msg.get("Date") or "").strip()

    from_list = extract_addrs(from_raw)
    to_list = extract_addrs(to_raw)
    cc_list = extract_addrs(cc_raw)
    bcc_list = extract_addrs(bcc_raw)

    date_iso = parse_date_iso(date_raw)
    body_text, _ = get_best_bodies(msg)

    fin_hits, tech_hits = fin_tech_hits(body_text)
    rec = {
        "from": from_list[0] if from_list else None,
        "from_list": from_list,
        "to_list": to_list,
        "cc_list": cc_list,
        "bcc_list": bcc_list,
        "subject": subject or None,
        "date": date_iso,
        "body_text": body_text or None,
        "word_count": word_count(body_text),
        "fin_score": fin_hits,
        "tech_score": tech_hits,
        "fintech_score": fintech_score(body_text),
        "size_bytes": size,
    }
    return rec

def qualifies(rec, min_words, max_words, min_score):
    if not rec["body_text"]:
        return False
    if rec["word_count"] < min_words or rec["word_count"] > max_words:
        return False
    if rec["fintech_score"] < min_score:
        return False
    return True

def combine_into_body_text(rec):
    to_flat = "; ".join(rec["to_list"]) if rec["to_list"] else ""
    cc_flat = "; ".join(rec["cc_list"]) if rec["cc_list"] else ""
    bcc_flat = "; ".join(rec["bcc_list"]) if rec["bcc_list"] else ""
    lines = [
        f"From: {rec['from'] or ''}".strip(),
        f"To: {to_flat}".strip(),
        f"Cc: {cc_flat}".strip(),
        f"Bcc: {bcc_flat}".strip(),
        f"Subject: {rec['subject'] or ''}".strip(),
        "",
        rec["body_text"] or ""
    ]
    return "\n".join(lines).strip()

def iter_person_dirs(root):
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if os.path.isdir(p):
            yield name, p

def iter_files_under(path):
    for dirpath, _, filenames in os.walk(path):
        for fn in filenames:
            yield os.path.join(dirpath, fn)

def main():
    ap = argparse.ArgumentParser(
        description="Select up to N qualifying emails per person; "
                    "combine headers+body into body_text; output JSONL+CSV with fin/tech scores, "
                    "checkpointing every 5 people."
    )
    ap.add_argument("--root", required=True, help="Path to maildir root")
    ap.add_argument("--json", required=True, help="Output JSONL path")
    ap.add_argument("--csv", required=True, help="Output CSV path")
    ap.add_argument("--target-total", type=int, default=2250, help="Stop once this many rows are selected")
    ap.add_argument("--per-person-cap", type=int, default=15, help="Max qualifying emails per person")
    ap.add_argument("--min-words", type=int, default=300, help="Minimum body word count")
    ap.add_argument("--max-words", type=int, default=800, help="Maximum body word count")
    ap.add_argument("--min-score", type=int, default=2, help="Minimum finance/technical richness score")
    args = ap.parse_args()

    root = os.path.abspath(args.root)

    # CSV columns: single combined body_text plus metadata and scores
    fieldnames_csv = [
        "person", "folder", "file_path", "word_count",
        "fin_score", "tech_score", "fintech_score", "body_text"
    ]

    seen_hashes = set()
    seen_files = set()
    people_done = 0
    rows_selected = 0

    print("Scanning person folders...", file=sys.stderr)

    # open outputs once, stream+append records as we go
    with open(args.json, "w", encoding="utf-8", newline="") as jf, \
         open(args.csv, "w", encoding="utf-8", newline="") as cf:

        writer = csv.DictWriter(cf, fieldnames=fieldnames_csv)
        writer.writeheader()

        for person, person_path in iter_person_dirs(root):
            if rows_selected >= args.target_total:
                break

            qualifiers = []

            for path in iter_files_under(person_path):
                if len(qualifiers) >= args.per_person_cap:
                    break  # reached cap for this person

                try:
                    rec = parse_email_file(path)
                except Exception:
                    continue

                if not qualifies(rec, args.min_words, args.max_words, args.min_score):
                    continue

                body_hash = content_hash(rec["body_text"])
                file_key = os.path.abspath(path)
                if body_hash in seen_hashes or file_key in seen_files:
                    continue

                rel = os.path.relpath(path, root)
                folder = os.path.dirname(rel).replace("\\", "/")

                rec["person"] = person
                rec["folder"] = folder
                rec["file_path_abs"] = file_key
                rec["body_hash"] = body_hash

                qualifiers.append(rec)

            if qualifiers:
                mid = (args.min_words + args.max_words) // 2

                def rank_key(r):
                    wc_delta = abs((r["word_count"] or 0) - mid)
                    date_key = r["date"] or ""
                    return (-r["fintech_score"], wc_delta, -len(date_key))

                qualifiers.sort(key=rank_key)
                take = qualifiers[:args.per_person_cap]

                for r in take:
                    if rows_selected >= args.target_total:
                        break

                    combined_text = combine_into_body_text(r)

                    out_rec = {
                        "person": r["person"],
                        "folder": r["folder"],
                        "file_path": r["file_path_abs"],
                        "word_count": r["word_count"],
                        "fin_score": r["fin_score"],
                        "tech_score": r["tech_score"],
                        "fintech_score": r["fintech_score"],
                        "body_text": combined_text,
                    }

                    # JSONL line
                    jf.write(json.dumps(out_rec, ensure_ascii=False) + "\n")
                    # CSV row
                    writer.writerow(out_rec)

                    rows_selected += 1
                    seen_hashes.add(r["body_hash"])
                    seen_files.add(r["file_path_abs"])

            people_done += 1

            # checkpoint every 5 people
            if people_done % 5 == 0:
                jf.flush()
                cf.flush()
                os.fsync(jf.fileno())
                os.fsync(cf.fileno())
                print(
                    f"[CHECKPOINT] Processed {people_done} people; rows={rows_selected}",
                    file=sys.stderr
                )

        # final flush
        jf.flush()
        cf.flush()
        os.fsync(jf.fileno())
        os.fsync(cf.fileno())

    print(f"Final rows: {rows_selected}; people processed: {people_done}", file=sys.stderr)


if __name__ == "__main__":
    main()
