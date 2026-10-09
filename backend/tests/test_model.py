from app.services import model


def test_predict_returns_score_in_range():
    result = model.predict("http://secure-paypal-login.verify-account.tk")
    assert result.status == "ready"
    assert 0 <= result.risk_score <= 100
    assert result.label == "phishing"


def test_predict_returns_not_ready_on_error(monkeypatch):
    import model_integration

    def broken(url):
        raise RuntimeError("모델 오류")

    monkeypatch.setattr(model_integration, "predict_model", broken)
    result = model.predict("https://example.com")
    assert result.status == "not_ready"
    assert result.risk_score is None and result.label is None
