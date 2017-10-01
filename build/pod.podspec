Pod::Spec.new do |spec|
  spec.name         = 'Idd'
  spec.version      = '{{.Version}}'
  spec.license      = { :type => 'GNU Lesser General Public License, Version 3.0' }
  spec.homepage     = 'https://github.com/ariseid/ariseid-core'
  spec.authors      = { {{range .Contributors}}
		'{{.Name}}' => '{{.Email}}',{{end}}
	}
  spec.summary      = 'iOS AriseID Client'
  spec.source       = { :git => 'https://github.com/ariseid/ariseid-core.git', :commit => '{{.Commit}}' }

	spec.platform = :ios
  spec.ios.deployment_target  = '9.0'
	spec.ios.vendored_frameworks = 'Frameworks/Idd.framework'

	spec.prepare_command = <<-CMD
    curl https://iddstore.blob.core.windows.net/builds/{{.Archive}}.tar.gz | tar -xvz
    mkdir Frameworks
    mv {{.Archive}}/Idd.framework Frameworks
    rm -rf {{.Archive}}
  CMD
end
