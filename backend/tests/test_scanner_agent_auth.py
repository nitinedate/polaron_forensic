from app.services.scanner_agent_auth import hash_agent_token, mint_agent_token, token_hint


def test_mint_and_hash_stable():
    token = mint_agent_token()
    assert len(token) >= 32
    assert hash_agent_token(token) == hash_agent_token(token)
    assert hash_agent_token(token) != hash_agent_token(token + "x")
    assert token_hint(token) == token[-4:]
