def get_user(request):
    user_id = request.params["id"]
    # Unsafe: user input concatenated straight into the query.
    return db.query("SELECT * FROM users WHERE id = " + user_id)


def get_user_safe(request):
    user_id = request.params["id"]
    # Safe: parameterized query.
    return db.query("SELECT * FROM users WHERE id = ?", [user_id])
