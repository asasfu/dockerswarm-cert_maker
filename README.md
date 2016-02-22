# dockerswarm-cert_maker
Certificate authority and signing using ruby and openssl for Docker swarm(or really anything where you need a quick small cert setup)

Meant to be used mainly with YAML.  
Make a yaml file in a directory such as /home/user/mycerts/testyaml.yaml
Populate the testyaml.yaml with:
```
---
basedir: '.'
node_name:
  - myserver.example.local 
  - myotherserver.example.local 
pas_wrd: 'my_ca_password_to_secure_key'
days: 1056
ca: true
ca_details:
  country: CA
  prov_state: BC
  city: Vancouver
  org: Super company with Potential
  org_unit: White collar department
  cn: ca_fqdn_should_match_one_of_your_node_names
  email: we_work@example.local
```

Then run ./deploy_ca.rb -y /path/to/testyaml.yaml
if you leave basedir as '.' then it will place the certificates in `/path/to` (location of yaml file) in the above example.

If you want to add additional signed certs using the same CA at a later time you can change the `ca: true` to `ca: false` and then just add another node_name array value with the client cert that you need.  This ensures not having to pass the password for the cert via shell, or you can allow stdin to ask for the cert, or pass it via cmd option.
`./deploy_ca.rb -n mynewserver.example.local -c false -p my_ca_password_to_secure_key` or `echo my_ca_password_to_secure_key | ./deploy_ca.rb -n mynewserver.example.local -c false` or finally without echo and it will prompt you for the key.
