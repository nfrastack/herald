{ pkgs, lib, config, inputs, ... }:

{
  packages = [ 
    pkgs.git
    pkgs.gnumake
  ];

  languages.go.enable = true;
}
