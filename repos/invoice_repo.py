def repo_get_invoice_by_id(user_id):
    query = f"SELECT * FROM invoices WHERE id = {user_id}"
    return cursor.execute(query)
