defmodule Ueberauth.Strategy.Menshen.OAuth do
  @moduledoc """
  An implementation of OAuth2 for github.
  To add your `client_id` and `client_secret` include these values in your configuration.

  config :ueberauth, Ueberauth.Strategy.Menshen.OAuth,
        client_id: System.get_env("MENSHEN_CLIENT_ID"),
        client_secret: System.get_env("MENSHEN_CLIENT_SECRET")
  """
  use OAuth2.Strategy

  @defaults [
    strategy: __MODULE__,
    site: "http://localhost:3000",
    authorize_url: "/oauth/authorize",
    # token_url: "https://github.com/login/oauth/access_token",
  ]

  @doc """
  Construct a client for requests to Github.
  Optionally include any OAuth2 options here to be merged with the defaults.
  Ueberauth.Strategy.Github.OAuth.client(redirect_uri: "http://localhost:4000/auth/github/callback")
  This will be setup automatically for you in `Ueberauth.Strategy.Github`.
  These options are only useful for usage outside the normal callback phase of Ueberauth.
  """
  def client(opts \\ []) do
    config =
      :ueberauth
      |> Application.fetch_env!(Ueberauth.Strategy.Menshen.OAuth)
      |> check_config_key_exists(:client_id)
      |> check_config_key_exists(:client_secret)

    client_opts =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)

    OAuth2.Client.new(client_opts)
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth. No need to call this usually.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def get_token!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.get_token!(params)
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_param("client_secret", client.client_secret)
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end

  defp check_config_key_exists(config, key) when is_list(config) do
    unless Keyword.has_key?(config, key) do
      raise "#{inspect (key)} missing from config :ueberauth, Ueberauth.Strategy.Menshen"
    end
    config
  end
  defp check_config_key_exists(_, _) do
    raise "Config :ueberauth, Ueberauth.Strategy.Menshen is not a keyword list, as expected"
  end
end
