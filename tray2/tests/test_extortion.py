"""v2 협박 메일 탐지: 암호화폐 지갑 + 협박 지표 결합."""

from mailshield2.threats import find_crypto_wallets, scan_extortion_text

VALID_BTC = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
ETH = "0x52908400098527886E0F7030069857D2E4169EE7"


def test_valid_btc_address_checksum():
    assert VALID_BTC in find_crypto_wallets(f"보내세요 {VALID_BTC} 지금")
    assert find_crypto_wallets("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3") == []


def test_bech32_and_eth_addresses():
    found = find_crypto_wallets(f"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq 또는 {ETH}")
    assert len(found) == 2


def test_sextortion_mail_is_high():
    text = ("I installed malware on your device and recorded you through your webcam. "
            f"Send 0.5 bitcoin to {VALID_BTC} within 48 hours or I will send the video to all your contacts.")
    report = scan_extortion_text(text)
    assert report.risk == "high"
    assert report.wallets == 1
    assert {"malware", "webcam", "threat"} & set(report.signals)


def test_korean_extortion_mail_is_high():
    text = (f"당신의 PC에 악성 코드를 심어 웹캠으로 녹화했습니다. 48시간 이내에 비트코인 {VALID_BTC} 로 송금하지 않으면 "
            "지인 연락처 전체에 영상을 유포하겠습니다.")
    assert scan_extortion_text(text).risk == "high"


def test_wallet_without_threat_context_is_not_high():
    report = scan_extortion_text(f"후원 지갑 주소는 {VALID_BTC} 입니다. 감사합니다.")
    assert report.risk == "safe"


def test_crypto_newsletter_is_not_flagged():
    assert scan_extortion_text("Bitcoin price rose 5% today. Read our market report.").risk == "safe"
