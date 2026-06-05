# Context Aware Access Automation
# Opendaylight

## Prerequisites
1. intall java 8
```
sudo apt-get update
sudo apt-get install openjdk-8-jre
echo 'export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64/jre' >> ~/.bashrc
source ~/.bashrc
```

2. install karaf 0.8.4
```
cd ~
wget https://nexus.opendaylight.org/content/repositories/opendaylight.release/org/opendaylight/integration/karaf/0.8.4/karaf-0.8.4.tar.gz
tar -xvzf karaf-0.8.4.tar.gz
```

## git clone
Repository should be cloned into your home directory
```
cd ~
git clone https://github.com/shallwe-dance/DMINS_group6.git -b opendaylight
```


## How to run
1. run karaf
```
cd ~
./karaf-0.8.4/bin/karaf clean
```

2. open another terminal and run engine.py
```
cd ~/DMINS_group6
python3 engine.py
```

## How to replicate experiment
1. Run engine.py at ODL vm
2. Execute following command at Mininet vm
```
sudo python3 ./vpn_ssh_experiment.py
```
