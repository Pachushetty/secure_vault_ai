from app import app
from db import get_db

def test_navbar():
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO users (email, name, auth_provider) VALUES (%s, %s, %s) ON CONFLICT (email) DO NOTHING",
                    ('testuser@example.com', 'Test User', 'local'))
        db.commit()

    c = app.test_client()

    # 1. Logged-out state
    res_out = c.get('/').data.decode('utf-8')
    nav_out = res_out.split('id="mainNavbar"')[1].split('</nav>')[0]
    print("=== Logged-Out Navbar Tests ===")
    assert 'Home' in nav_out, "Home link should be in logged out navbar"
    assert 'Vault AI' in nav_out, "Vault AI should be in logged out navbar"
    assert 'Login' in nav_out, "Login button should be in logged out navbar"
    assert 'Sign Up' in nav_out, "Sign Up button should be in logged out navbar"
    assert 'My Vault' not in nav_out, "My Vault should NOT be in logged out navbar"
    assert 'Activity' not in nav_out, "Activity should NOT be in logged out navbar"
    assert 'Security' not in nav_out, "Security should NOT be in logged out navbar"
    assert 'userDropdown' not in nav_out, "User dropdown should NOT be in logged out navbar"
    assert 'New Folder' not in nav_out, "New Folder should NOT be in logged out navbar"
    print("[OK] Logged-out navbar passed all assertions!")

    # 2. Logged-in state
    with c.session_transaction() as sess:
        sess['user_email'] = 'testuser@example.com'
        sess['user_name'] = 'Test User'

    res_in = c.get('/').data.decode('utf-8')
    nav_in = res_in.split('id="mainNavbar"')[1].split('</nav>')[0]
    print("\n=== Logged-In Navbar Tests ===")
    assert 'Home' in nav_in, "Home link should be in logged in navbar"
    assert 'My Vault' in nav_in, "My Vault link should be in logged in navbar"
    assert 'Vault AI' in nav_in, "Vault AI link should be in logged in navbar"
    assert 'Activity' in nav_in, "Activity link should be in logged in navbar"
    assert 'Security' in nav_in, "Security link should be in logged in navbar"
    assert 'userDropdown' in nav_in, "User dropdown should be present in logged in navbar"
    assert 'Profile' in nav_in, "Profile item should be in user dropdown"
    assert 'Settings' in nav_in, "Settings item should be in user dropdown"
    assert 'Logout' in nav_in, "Logout item should be in user dropdown"
    assert 'New Folder' not in nav_in, "New Folder should NOT be in global navbar"
    assert 'Login' not in nav_in, "Login button should NOT be in logged in navbar"
    assert 'Sign Up' not in nav_in, "Sign Up button should NOT be in logged in navbar"
    print("[OK] Logged-in navbar passed all assertions!")

    # 3. Test page loads for all authenticated routes
    print("\n=== Authenticated Route Responses ===")
    for route in ['/dashboard', '/activity', '/security', '/profile', '/settings', '/vault-ai']:
        res = c.get(route)
        assert res.status_code == 200, f"Route {route} returned {res.status_code}"
        print(f"[OK] {route} -> 200 OK")

    print("\nALL VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == '__main__':
    test_navbar()
