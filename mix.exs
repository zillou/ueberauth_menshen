defmodule UeberauthMenshen.MixProject do
  use Mix.Project

  def project do
    [
      app: :ueberauth_menshen,
      version: "0.1.0",
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:oauth2, "~> 0.9.4"},
      {:ueberauth, "~> 0.5.0"}
    ]
  end
end
