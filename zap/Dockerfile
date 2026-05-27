FROM ghcr.io/zaproxy/zaproxy:stable

COPY addons.txt /zap/addons.txt

# Refresh marketplace index, then install each add-on from the list
RUN zap.sh -cmd -addonupdate && \
    grep -vE '^\s*(#|$)' /zap/addons.txt | awk '{print $1}' | \
    while read addon; do \
      echo "Installing: ${addon}"; \
      zap.sh -cmd -addoninstall "${addon}" || \
      echo "WARN: Failed to install ${addon}"; \
    done
