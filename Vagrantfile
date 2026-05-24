Vagrant.configure("2") do |config|
  config.vm.box_check_update = false

  machines = [
    { name: "suricata", box: "ubuntu/jammy64", ip: "192.168.56.11" },
    { name: "kali", box: "kalilinux/rolling", ip: "192.168.56.12" },
    { name: "webserver", box: "ubuntu/jammy64", ip: "192.168.56.14" },
    { name: "sensor", box: "ubuntu/jammy64", ip: "192.168.56.13" }
  ]

  machines.each do |machine|
    config.vm.define machine[:name] do |node|
      node.vm.box = machine[:box]
      node.vm.hostname = machine[:name]

      # Internet
      node.vm.network "forwarded_port", guest: 22, host: 2200 + machines.index(machine), auto_correct: true

      # Internal network
      node.vm.network "private_network", ip: machine[:ip]
      if machine[:name] == "suricata"
        node.disksize.size = "100GB"
        node.vm.synced_folder "D:/Datasets/pcap", "/home/vagrant/pcap", type: "virtualbox"
        node.vm.synced_folder "D:/Datasets/labels", "/home/vagrant/labels", type: "virtualbox"
        node.vm.synced_folder "D:/Lab/results", "/home/vagrant/qef-results/suricata/phase2", type: "virtualbox"
      end
      node.vm.provider "virtualbox" do |vb|
        vb.name = machine[:name]
        vb.memory = 2048
        vb.cpus = 2

        # Promiscuous mode for IDS visibility
        vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
      end

      # Common provisioning
      node.vm.provision "shell", inline: <<-SHELL
        sudo apt-get update -y
        sudo apt-get install -y curl wget net-tools
      SHELL

      # 🟢 Suricata setup
      if machine[:name] == "suricata"
        node.vm.provision "shell", inline: <<-SHELL
          sudo apt-get install software-properties-common
          sudo add-apt-repository ppa:oisf/suricata-stable
          sudo sudo apt-get update
          sudo apt-get install -y suricata

          # Enable community rules
          sudo suricata-update

          # Set interface to eth1 (private network)
          sudo sed -i 's/interface: eth0/interface: eth1/' /etc/suricata/suricata.yaml

          # Start Suricata
          sudo systemctl restart suricata

          echo "Suricata started on eth1"
        SHELL
      end

      # 🔴 Webserver setup (victim)
      if machine[:name] == "webserver"
        node.vm.provision "shell", inline: <<-SHELL
          sudo apt-get install -y apache2

          echo "<h1>Vulnerable Web Server</h1>" | sudo tee /var/www/html/index.html

          sudo systemctl enable apache2
          sudo systemctl start apache2
        SHELL
      end

      # ⚫ Sensor (traffic generator)
      if machine[:name] == "sensor"
        node.vm.provision "shell", inline: <<-SHELL
          sudo apt-get install -y iperf3

          # Run traffic generator in background
          nohup iperf3 -s &
        SHELL
      end

      # 🔴 Kali (attacker tools)
      if machine[:name] == "kali"
        node.vm.provision "shell", inline: <<-SHELL
          sudo apt-get update
          sudo apt-get install -y nmap hydra hping3 curl
        SHELL
      end

    end
  end
end