defmodule Ueberauth.Strategy.Menshen do
  use Ueberauth.Strategy, uid_field: :id,
                          default_scope: "",
                          oauth2_module: Ueberauth.Strategy.Menshen.OAuth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @doc """
  Handles the initial redirect to the github authentication page.
  To customize the scope (permissions) that are requested by github include them as part of your url:
      "/auth/github?scope=user,public_repo,gist"
  You can also include a `state` param that github will return to you.
  """
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    send_redirect_uri = Keyword.get(options(conn), :send_redirect_uri, true)

    opts =
      if send_redirect_uri do
        [redirect_uri: callback_url(conn), scope: scopes]
      else
        [scope: scopes]
      end

    opts =
      if conn.params["state"], do: Keyword.put(opts, :state, conn.params["state"]), else: opts

    module = option(conn, :oauth2_module)
    redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  @doc """
  Handles the callback from Menshen. When there is a failure from Menshen the failure is included in the
  `ueberauth_failure` struct. Otherwise the information returned from Menshen is returned in the `Ueberauth.Auth` struct.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    IO.inspect(callback_url(conn))

    opts = [redirect_uri: callback_url(conn)]

    client = Ueberauth.Strategy.Menshen.OAuth.get_token!([code: code], opts)
    token = client.token

    if token.access_token == nil do
      err = token.other_params["error"]
      desc = token.other_params["error_description"]
      set_errors!(conn, [error(err, desc)])
    else
      fetch_user(conn, client)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used for passing the raw Github response around during the callback.
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:github_user, nil)
    |> put_private(:github_token, nil)
  end

  def uid(conn) do
    "id"
  end

  @doc """
  Includes the credentials from the Github response.
  """
  def credentials(conn) do
    token        = conn.private.token
    scope_string = (token.other_params["scope"] || "")
    scopes       = String.split(scope_string, ",")

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at,
      scopes: scopes
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.user

    %Info{
      email: user["email"],
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the Github callback.
  """
  def extra(conn) do
    %Extra {}
  end

  defp fetch_user(conn, client) do
    conn = put_private(conn, :token, client.token)
    path = "/api/v1/me"
    case OAuth2.Client.get(client, path) do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])
      {:ok, %OAuth2.Response{status_code: status_code, body: user}}
        when status_code in 200..399 ->
        put_private(conn, :user, user)
      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end
