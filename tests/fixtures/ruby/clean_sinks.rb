class UsersController
  def search_safe
    name = params[:name]
    # parameterized query — the placeholder string (checked) and the bound
    # value (NOT checked, it's a separate argument) are kept apart, same
    # as the other languages' clean fixtures. Unlike python/js/go's DB
    # clients, raw ActiveRecord#execute has no params argument at all —
    # exec_query does, so that's the realistic safe-usage example here.
    ActiveRecord::Base.connection.exec_query("SELECT * FROM users WHERE name = ?", "SQL", [[nil, name]])  # safe: SQL Injection
  end

  def ping_safe
    # fixed, non-tainted argument
    system("echo hello")  # safe: Command Injection
  end

  def go_safe
    # same-origin relative path — not an open redirect
    redirect_to "/dashboard"  # safe: Open Redirect
  end

  def show_name_safe
    name = params[:name]
    # ERB's default auto-escaping applies — html_safe was never called
    render html: name  # safe: Cross-Site Scripting (XSS)
  end
end
