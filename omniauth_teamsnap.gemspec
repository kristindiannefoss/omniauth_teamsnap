# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require_relative "lib/omniauth-teamsnap/version"

Gem::Specification.new do |s|
  s.name        = "omniauth-teamsnap"
  s.version     = OmniAuth::TeamSnap::VERSION
  s.authors     = ["Kristin Dianne Foss", "Josh Cheek"]
  s.email       = ["kris.foss@gmail.com"]
  s.homepage    = "https://github.com/kristindiannefoss/omniauth-teamsnap"
  s.description = "OmniAuth strategy for TeamSnap"
  s.summary     = s.description
  s.license     = "MIT"
  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_dependency 'json', '~> 1.3'
  s.add_dependency 'omniauth-oauth2', '~> 1.2'
  s.add_development_dependency 'bundler', '~> 1.0'
end
