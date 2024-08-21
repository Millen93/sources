#!/bin/bash

# Print help
help() {
printf "
Usage: validate.sh [OPTION]...
Validate installation of https://github.com/Millen93/Nginx-Monitoring

Syntax: validate.sh --all

  -h, --help                 display this help and exit;
  -n, --nginx                validate nginx installation https://github.com/Millen93/Nginx-Monitoring?tab=readme-ov-file#install-nginx;
  -e, --nginx_exporter       validate nginx_exporter installation https://github.com/Millen93/Nginx-Monitoring?tab=readme-ov-file#install-nginx-prometheus-exporter;
  -z, --zeek                 validate zeek installation https://github.com/Millen93/Nginx-Monitoring?tab=readme-ov-file#install-zeek;
  -p, --prometheus           validate prometheus installation https://github.com/Millen93/Nginx-Monitoring?tab=readme-ov-file#install-prometheus;
  -m, --alertmanager         validate alertmanager installation https://github.com/Millen93/Nginx-Monitoring?tab=readme-ov-file#install-prometheus-alertmanager;
  -g, --grafana              validate grafana installation https://github.com/Millen93/Nginx-Monitoring?tab=readme-ov-file#install-grafana;
  -a, --all                  validate all services.
"
exit 0
}

# Check port status
check_port() {
    local port=$1
    if nc -zv 127.0.0.1 ${port} &> /dev/null; then
        echo "."
    else
        echo -e "\033[0;31mPort ${port} is not open. Please check the installation.\033[0m"
    fi
}

# Check service status
check_service() {
    local service=$1
    if systemctl is-active ${service} --quiet ; then
        echo -e "\033[0;32m${service} is active.\033[0m"
    else
        echo -e "\033[0;31m${service} is not active. Please check the ${service} installation.\033[0m"
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
      --help|-h)
      help
      ;;
      --nginx|-n)
      check_port 443
      check_port 8080
      check_service nginx
      ;;
      --nginx_exporter|-e)
      check_port 9113
      check_service nginx_exporter.service
      ;;
      --zeek|-z)
      check_port 4242
      check_service zeek.service
      ;;
      --prometheus|-p)
      check_port 9090
      check_service prometheus.service
      ;;
      --alertmanager|-m)
      check_port 9093
      check_service alertmanager.service
      ;;
      --grafana|-g)
      check_port 3000
      check_service grafana-server.service
      ;;
      --all|-a)
      check_port 443
      check_port 8080
      check_service nginx
      check_port 4242
      check_service zeek.service
      check_port 9090
      check_service prometheus.service
      check_port 9093
      check_service alertmanager.service
      check_port 3000
      check_service grafana-server.service
      ;;
      *)
      printf "validate: invalid option -- '${1}'\n"
      printf "Try 'validate --help' for more information.\n"
      exit 1
      ;;
    esac
    shift
done










