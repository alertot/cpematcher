{ pkgs, lib, config, inputs, ... }:
let
  root-dir = config.devenv.root;
in
{
  # https://devenv.sh/basics/

  # https://devenv.sh/packages/
  packages = [ pkgs.git ];

  # https://devenv.sh/languages/
  languages.python = {
    enable = true;
    version = "3.11";
    poetry = {
      enable = true;
      activate.enable = true;
      install.enable = true;
      install.verbosity = "little";
    };
  };

  # https://devenv.sh/scripts/

  # https://devenv.sh/tests/
  enterTest = ''
    echo "Running tests"
    python -m pytest tests/
  '';

  # https://devenv.sh/pre-commit-hooks/
  pre-commit.hooks = {
    ruff = {
      enable = true;
      args = [ "--config" "${root-dir}/pyproject.toml" ];
    };
    ruff-format.enable = true;
    check-added-large-files.enable = true;
    trim-trailing-whitespace = {
      enable = true;
      excludes = [ ".*.md$" ];
    };
    end-of-file-fixer.enable = true;
  };

  # See full reference at https://devenv.sh/reference/options/
}
