"""اختبارات الدخول التلقائي (كشف نموذج الدخول بلا LLM) + نقطة autoscan."""

from workers.autologin import auto_login, find_login_form

DVWA_LOGIN = """
<html><body>
<form action="login.php" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="hidden" name="user_token" value="tok-xyz">
  <input type="submit" name="Login" value="Login">
</form>
</body></html>
"""

GENERIC_LOGIN = """
<form action="/do-login" method="post">
  <input type="email" name="email" placeholder="email">
  <input type="password" name="pass">
  <input type="hidden" name="csrf" value="c1">
</form>
"""


def test_find_login_form_dvwa():
    form = find_login_form(DVWA_LOGIN)
    assert form["username_field"] == "username"
    assert form["password_field"] == "password"
    # الحقل المخفي وزر submit يُمرَّران تلقائيًا بقيمهما.
    assert form["payload"]["user_token"] == "tok-xyz"
    assert form["payload"]["Login"] == "Login"
    assert form["action"] == "login.php"


def test_find_login_form_generic_email():
    form = find_login_form(GENERIC_LOGIN)
    assert form["username_field"] == "email"     # رُجّح الاسم المألوف
    assert form["password_field"] == "pass"
    assert form["payload"]["csrf"] == "c1"


def test_find_login_form_none_when_no_password():
    assert find_login_form("<form><input name='q'></form>") is None


# ── عميل وهمي يحاكي GET/POST والكوكيز ──
class _Resp:
    def __init__(self, text, url=""):
        self.text = text
        self.url = url


class _FakeClient:
    def __init__(self, page, url="http://dvwa/login.php"):
        self._page = page
        self._url = url
        self.posted = None
        self.posted_url = None
        self._jar = {"PHPSESSID": "s1"}

    def get(self, url):
        return _Resp(self._page, self._url)

    def post(self, url, data):
        self.posted_url = url
        self.posted = data
        return _Resp("ok", url)

    def cookies(self):
        return self._jar


def test_auto_login_fills_detected_fields():
    client = _FakeClient(DVWA_LOGIN)
    cookies = auto_login(client, "http://dvwa/login.php", "admin", "password")

    # عبّأ الحقول المكتشَفة تلقائيًا + أبقى التوكن والزر.
    assert client.posted["username"] == "admin"
    assert client.posted["password"] == "password"
    assert client.posted["user_token"] == "tok-xyz"
    assert client.posted["Login"] == "Login"
    # action النسبي حُلّ مقابل عنوان الصفحة.
    assert client.posted_url == "http://dvwa/login.php"
    assert cookies["PHPSESSID"] == "s1"


def test_auto_login_no_form_returns_cookies_without_post():
    client = _FakeClient("<html>no login here</html>")
    cookies = auto_login(client, "http://x/", "admin", "password")
    assert client.posted is None          # لا إرسال بلا نموذج
    assert cookies == {"PHPSESSID": "s1"}


# ── نقطة autoscan ──
def _api_program(client):
    pid = client.post("/programs", json={"name": "DVWA", "handle": "dvwa"}).json()["id"]
    client.post(
        f"/programs/{pid}/scope",
        json={"kind": "domain", "identifier": "dvwa", "in_scope": True},
    )
    return pid


def test_autoscan_rejects_out_of_scope(client):
    pid = _api_program(client)
    r = client.post(f"/programs/{pid}/autoscan", json={"seed": "http://evil.com/"})
    assert r.status_code == 403


def test_autoscan_in_scope_passes_validation(client):
    pid = _api_program(client)
    # ضمن النطاق => يتجاوز الحارس ويحاول الجدولة (الطابور غير متاح => 503).
    r = client.post(f"/programs/{pid}/autoscan", json={"seed": "http://dvwa/"})
    assert r.status_code in (503, 200)
