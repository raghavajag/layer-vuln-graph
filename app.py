# Flask-like
@app.route("/invoice/<user_id>")
def get_invoice_route(user_id):
    if not user_id.isdigit():
        raise ValueError("bad id")
    return invoice_service_get(user_id)

def dead_controller(user_id):
    return invoice_service_dead(user_id)
