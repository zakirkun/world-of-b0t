FROM python:3.12-alpine

# TOKEN CRYPT :: seal box (World Of B0t challenge 12)
# Category: Crypto | Difficulty: hard | Vuln: semi-weak DES keys in triple DES

WORKDIR /app
COPY app/des.py app/server.py /app/

# Injected at runtime by the launcher. Empty here on purpose so nothing is
# baked into an image layer.
ENV W0B_FLAG=""
ENV PORT=8080

# No third-party packages: DES is hand-rolled and stdlib-only by design.
RUN python3 -c "import des; des._self_check()"

EXPOSE 8080
USER 10001
CMD ["python3", "server.py"]
