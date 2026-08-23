# This bootstrap follows the official Supabase self-hosted Supavisor configuration.
{:ok, _} = Application.ensure_all_started(:supavisor)

{:ok, version} =
  case Supavisor.Repo.query!("select version()") do
    %{rows: [[value]]} -> Supavisor.Helpers.parse_pg_version(value)
    _ -> nil
  end

params = %{
  "external_id" => System.fetch_env!("POOLER_TENANT_ID"),
  "db_host" => System.fetch_env!("POSTGRES_HOST"),
  "db_port" => System.fetch_env!("POSTGRES_PORT"),
  "db_database" => System.fetch_env!("POSTGRES_DB"),
  "require_user" => false,
  "auth_query" => "SELECT * FROM pgbouncer.get_auth($1)",
  "default_max_clients" => System.fetch_env!("POOLER_MAX_CLIENT_CONN"),
  "default_pool_size" => System.fetch_env!("POOLER_DEFAULT_POOL_SIZE"),
  "default_parameter_status" => %{"server_version" => version},
  "users" => [
    %{
      "db_user" => "pgbouncer",
      "db_password" => System.fetch_env!("POSTGRES_PASSWORD"),
      "mode_type" => System.fetch_env!("POOLER_POOL_MODE"),
      "pool_size" => System.fetch_env!("POOLER_DEFAULT_POOL_SIZE"),
      "is_manager" => true
    }
  ]
}

if !Supavisor.Tenants.get_tenant_by_external_id(params["external_id"]) do
  {:ok, _} = Supavisor.Tenants.create_tenant(params)
end
