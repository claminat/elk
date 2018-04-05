echo -n "Enter ELK Server IP or FQDN: "
read eip
echo -n "Enter Admin Web Password: "
read adpwd


#vi elk.sh
#chmod -R 777 elk.sh
#./elk.sh

#Utility
sudo yum install wget -y
sudo yum install apt-get -y
sudo yum install telnet -y
sudo yum install net-tools -y


#Update System
yum update -y
yum upgrade -y

#Java 
yum install java-1.8.0-openjdk -y
yum update -y

#DISABLE SELINUX
sed -i '5 d' /etc/sysconfig/selinux
sed '5 i SELINUX=disabled' /etc/sysconfig/selinux
getenforce

#Firewall Configuration
yum install firewalld -y
systemctl unmask firewalld
systemctl enable firewalld
systemctl start firewalld
firewall-cmd --list-all

firewall-cmd --permanent --zone=public --add-port=80/tcp
firewall-cmd --permanent --zone=public --add-port=5044/tcp
firewall-cmd --permanent --zone=public --add-port=5601/tcp
firewall-cmd --permanent --zone=public --add-port=9100/tcp
firewall-cmd --permanent --zone=public --add-port=9200/tcp
firewall-cmd --permanent --zone=public --add-port=9300/tcp

firewall-cmd --reload
netstat -plntu

#Elastic Search
sudo wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-5.6.2.rpm
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
rpm --install elasticsearch-5.6.2.rpm
sed '1 i network.host: 0.0.0.0' /etc/elasticsearch/elasticsearch.yml

systemctl daemon-reload
systemctl start elasticsearch
systemctl enable elasticsearch
systemctl status elasticsearch

#Kibana

wget https://artifacts.elastic.co/downloads/kibana/kibana-5.6.2-x86_64.rpm
sudo rpm --install kibana-5.6.2-x86_64.rpm
cat <<EOF > /etc/kibana/kibana.yml
server.host: "0.0.0.0"
EOF

sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable kibana.service
sudo systemctl start kibana.service
sudo systemctl status kibana.service

#NGINX Reverse Proxy
sudo yum -y install nginx
sudo yum -y install epel-release
sudo yum -y install httpd-tools

mkdir /etc/nginx/
touch /etc/nginx/htpasswd.users
echo "admin:`openssl passwd -apr1 $adpwd`" | sudo tee -a /etc/nginx/htpasswd.users

sed -i '38,57d' /etc/nginx/nginx.conf


cat <<EOT > /etc/nginx/conf.d/kibana.conf
server {
    listen 80;

    server_name $eip;
    
    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/htpasswd.users;
    
    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \\\$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \\\$host;
        proxy_cache_bypass \\\$http_upgrade;        
    }
}
EOT

nginx -t
sudo systemctl start nginx
sudo systemctl enable nginx
sudo systemctl status nginx

#LogStash
cat <<EOF > /etc/yum.repos.d/logstash.repo
[logstash-5.x]
name=Elastic repository for 5.x packages
baseurl=https://artifacts.elastic.co/packages/5.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

sudo yum install logstash -y

sudo mkdir -p /etc/pki/tls/certs
sudo mkdir /etc/pki/tls/private
cd /etc/pki/tls; sudo openssl req -subj '/CN='$eip'/' -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt


cat <<EOF > /etc/logstash/conf.d/input.conf
input {
	beats {
		port => 5044
		ssl => true
		ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
		ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
	}
}
EOF



cat <<EOF > /etc/logstash/conf.d/output.conf
output {
	elasticsearch {
		hosts => ["localhost:9200"]
		sniffing => true
		manage_template => false
		index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
		document_type => "%{[@metadata][type]}"
	}
}
EOF

cat <<EOF > /etc/logstash/conf.d/filter.conf
filter {
	if [type] == "syslog" {
		grok {
		match => { "message" => "%{SYSLOGLINE}" }
		}
		date {
			match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
		}
	}
}
EOF

sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
systemctl daemon-reload
systemctl start logstash
systemctl enable logstash
systemctl status logstash

#Filebeat

cat <<EOF > /etc/yum.repos.d/filebeat.repo
[elastic-5.x]
name=Elastic repository for 5.x packages
baseurl=https://artifacts.elastic.co/packages/5.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

yum install filebeat -y

cat <<EOT > /etc/filebeat/filebeat.yml
#=========================== Filebeat prospectors =============================
filebeat.prospectors:
- input_type: log

  # Paths that should be crawled and fetched. Glob based paths.
  paths:
    - /var/log/*.log
    #- c:\programdata\elasticsearch\logs\*

- document_type: syslog
  paths:
    - /var/log/syslog

#-------------------------- Elasticsearch output ------------------------------
output.elasticsearch:
  # Array of hosts to connect to.
  hosts: ["localhost:9200"]

#----------------------------- Logstash output --------------------------------
output.logstash:
  
  hosts: ["$eip:5044"]
  bulk_max_size: 1024
  ssl.certificate_authorities: ["/etc/pki/tls/certs/logstash-forwarder.crt"]
  template.name: "filebeat"
  template.path: "filebeat.template.json"
  template.overwrite: false

EOT

systemctl start filebeat
systemctl enable filebeat
systemctl status filebeat

reboot
