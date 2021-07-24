#!/usr/bin/env ruby

require 'nokogiri'
require 'fileutils'

VER = "1.0.0"

FLAGS = {
	'R' => 'PIV_SUPPORT_RSA',
	'E' => 'PIV_SUPPORT_EC',
	'e' => 'PIV_SUPPORT_ECCP384',
	'P' => 'PIV_USE_EC_PRECOMPHASH',
	'S' => 'PIV_STRICT_CONTACTLESS',
	'A' => 'YKPIV_ATTESTATION',
	'x' => 'APPLET_EXTLEN',
	'L' => 'APPLET_LOW_TRANSIENT',
	'a' => 'PIV_SUPPORT_AES',
	'D' => 'PIV_SUPPORT_3DES'
}

puts "PIVApplet Build Started..."
if (ENV['JC_SDKS'].nil?)
	puts "ERROR: SDK path must be set"
	exit (1)
else
	puts "SDK Path: " + ENV['JC_SDKS']
end

$xmlbase = Nokogiri::XML(File.open('build.xml'))
FLAGS.each do |_,fl|
	a = $xmlbase.xpath("//property[@name='#{fl}']")
	a[0]['value'] = 'false'
end

def setup_config(jcver, flags)
	buildxml = $xmlbase.dup
	flags.split('').each do |flabbr|
		fl = FLAGS[flabbr]
		a = buildxml.xpath("//property[@name='#{fl}']")
		a[0]['value'] = 'true'
	end
	f = File.open('build.xml', 'w')
	f.write(buildxml.to_s)
	f.close()
	ENV['JC_HOME'] = ENV['JC_SDKS'] + "/#{jcver}_kit"
end

def build(ver, jcver, flags)
	setup_config(jcver, flags)
	`ant clean`
	`ant`
	FileUtils.mv('bin/PivApplet.cap', "dist/PivApplet-#{ver}-#{jcver}-#{flags}.cap")
end

`rm -fr dist`
`mkdir dist`
build(VER, 'jc222', 'RESAxaD')

build(VER, 'jc304', 'REePSAxa')
build(VER, 'jc304', 'REePSAxaD')
