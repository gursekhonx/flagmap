class UsersController
  def search
    name = params[:name]
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    ActiveRecord::Base.connection.execute(sql)  # ruleid: SQL Injection
  end

  def ping
    host = params[:host]
    cmd = "ping -c 1 " + host
    system(cmd)  # ruleid: Command Injection
  end

  def read_file
    fname = params[:fname]
    File.open(fname)  # ruleid: Path Traversal / LFI
  end

  def go
    url = params[:url]
    redirect_to url  # ruleid: Open Redirect
  end

  def show_name
    name = params[:name]
    render html: name.html_safe  # ruleid: Cross-Site Scripting (XSS)
  end

  def load_data
    data = params[:data]
    Marshal.load(data)  # ruleid: Unsafe Deserialization
  end

  def run_query(sql)
    ActiveRecord::Base.connection.execute(sql)  # ruleid: SQL Injection
  end

  def search2
    # one-hop interprocedural: `sql` is tainted at the call site below,
    # which must seed run_query's own `sql` parameter for the sink inside
    # it to fire.
    name = params[:name]
    run_query("SELECT * FROM users WHERE name = '" + name + "'")
  end
end
