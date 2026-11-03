# ==========================================
# STAGE 1: Tool Downloader (Static Archives)
# ==========================================
FROM ubuntu:24.04 AS downloader

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Ghidra Headless
ARG GHIDRA_VER=11.2
ARG GHIDRA_DATE=20240926
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VER}_build/ghidra_${GHIDRA_VER}_PUBLIC_${GHIDRA_DATE}.zip" -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VER}_PUBLIC /opt/ghidra \
    && rm /tmp/ghidra.zip

# JADX CLI
ARG JADX_VER=1.5.0
RUN wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip" -O /tmp/jadx.zip \
    && mkdir -p /opt/jadx \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && rm /tmp/jadx.zip

# Apktool Wrapper & Jar
ARG APKTOOL_VER=2.10.0
RUN mkdir -p /opt/apktool \
    && curl -fsSL https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -o /opt/apktool/apktool \
    && curl -fsSL "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VER}/apktool_${APKTOOL_VER}.jar" -o /opt/apktool/apktool.jar \
    && chmod +x /opt/apktool/apktool /opt/apktool/apktool.jar

# Mandiant capa + rules
ARG CAPA_VER=8.0.1
RUN mkdir -p /opt/capa \
    && wget -q "https://github.com/mandiant/capa/releases/download/v${CAPA_VER}/capa-v${CAPA_VER}-linux.zip" -O /tmp/capa.zip \
    && unzip -q /tmp/capa.zip -d /opt/capa \
    && chmod +x /opt/capa/capa \
    && rm /tmp/capa.zip \
    && git clone --depth 1 -b "v${CAPA_VER}" https://github.com/mandiant/capa-rules.git /opt/capa/rules \
    && rm -rf /opt/capa/rules/.git

# Mandiant GoReSym (Go symbol & struct recovery)
ARG GORESYM_VER=3.0.1
RUN mkdir -p /opt/goresym \
    && wget -q "https://github.com/mandiant/GoReSym/releases/download/v${GORESYM_VER}/GoReSym-linux.zip" -O /tmp/goresym.zip \
    && unzip -q /tmp/goresym.zip -d /opt/goresym \
    && if [ -f /opt/goresym/GoReSym_linux ]; then mv /opt/goresym/GoReSym_linux /opt/goresym/GoReSym; fi \
    && chmod +x /opt/goresym/* \
    && rm /tmp/goresym.zip

# Detect-It-Easy CLI (diec) + signature & YARA databases (PEiD, packers, crypto)
ARG DIE_VER=3.21
RUN curl -fsSL "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VER}/die_${DIE_VER}_Ubuntu_24.04_amd64.deb" -o /tmp/die.deb \
    && dpkg-deb -x /tmp/die.deb /tmp/die \
    && mkdir -p /opt/die/bin \
    && cp /tmp/die/usr/bin/diec /opt/die/bin/diec \
    && cp -r /tmp/die/usr/lib/die /opt/die/lib \
    && chmod +x /opt/die/bin/diec \
    && rm -rf /tmp/die /tmp/die.deb

# Community YARA Rules collection (packers, crypto, anti-debug, capabilities)
RUN git clone --depth 1 https://github.com/Yara-Rules/rules.git /opt/yara-rules \
    && rm -rf /opt/yara-rules/.git


# ==========================================
# STAGE 2: Native C / C++ / Rust Builder
# (Radare2, pycdc, and Motorola dsp56300-disasm / dsp56300-asm)
# ==========================================
FROM ubuntu:24.04 AS cpp-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Build Radare2
RUN git clone --depth 1 https://github.com/radareorg/radare2.git /tmp/radare2 \
    && cd /tmp/radare2 \
    && ./configure --prefix=/opt/radare2 \
    && make -j"$(nproc)" \
    && make install

# Build pycdc (Decompyle++ for Python bytecode decompilation)
RUN git clone --depth 1 https://github.com/zrax/pycdc.git /tmp/pycdc \
    && cmake -S /tmp/pycdc -B /tmp/pycdc/build -DCMAKE_INSTALL_PREFIX=/opt/pycdc \
    && cmake --build /tmp/pycdc/build -j"$(nproc)" \
    && cmake --install /tmp/pycdc/build

# Build BinHexConv (Universal Binary <-> Hex-text Converter from mat-ocl/binhexconv)
RUN git clone --depth 1 https://github.com/mat-ocl/binhexconv.git /tmp/binhexconv \
    && mkdir -p /opt/binhexconv/bin \
    && SRC_DIR="$(dirname "$(find /tmp/binhexconv -name 'Converter.cpp' | head -n 1)")" \
    && g++ -O3 -std=c++17 -I"${SRC_DIR}" "${SRC_DIR}/BinHexConv.cpp" "${SRC_DIR}/Converter.cpp" -o /opt/binhexconv/bin/binhexconv \
    && ln -s /opt/binhexconv/bin/binhexconv /opt/binhexconv/bin/bin2hext \
    && strip /opt/binhexconv/bin/binhexconv \
    && rm -rf /tmp/binhexconv

# Build Motorola DSP56300 Disassembler & Assembler (xemu-project/dsp56300)
ENV RUSTUP_HOME=/tmp/rustup \
    CARGO_HOME=/tmp/cargo \
    PATH="/tmp/cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && git clone --depth 1 https://github.com/xemu-project/dsp56300.git /tmp/dsp56300 \
    && mkdir -p /opt/dsp56300/bin \
    && cargo install --path /tmp/dsp56300/crates/disasm --root /opt/dsp56300 \
    && (cargo install --path /tmp/dsp56300/crates/asm --root /opt/dsp56300 || true) \
    && strip /opt/dsp56300/bin/dsp56300-* 2>/dev/null || true \
    && rm -rf /tmp/dsp56300 /tmp/rustup /tmp/cargo


# ==========================================
# STAGE 3: Python Environment Builder
# ==========================================
FROM ubuntu:24.04 AS python-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    liblzma-dev \
    liblzo2-dev \
    libssl-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/re-venv \
    && /opt/re-venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel \
    && /opt/re-venv/bin/pip install --no-cache-dir \
        flare-floss \
        frida-tools \
        openai \
        "mcp[cli]" \
        pyinstxtractor-ng \
        lief \
        pefile \
        pyelftools \
        r2pipe \
        yara-python \
        capstone \
    && find /opt/re-venv -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true \
    && find /opt/re-venv -type d -name "tests" -exec rm -rf {} + 2>/dev/null || true


# ==========================================
# STAGE 4: Final Lean & Hardened Runtime Image
# ==========================================
FROM ubuntu:24.04 AS final

ENV DEBIAN_FRONTEND=noninteractive \
    JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    LD_LIBRARY_PATH="/opt/radare2/lib" \
    PATH="/opt/radare2/bin:/opt/re-venv/bin:/opt/dsp56300/bin:/opt/binhexconv/bin:/opt/jadx/bin:/opt/ghidra/support:/opt/apktool:/opt/capa:/opt/goresym:/opt/pycdc/bin:/opt/dotnet-tools:${PATH}"

# Install runtimes, unpackers, WASM tools, .NET SDK, LLVM/LLDB, DIE deps, and dynamic tracers
RUN apt-get update && apt-get install -y --no-install-recommends \
    gosu \
    ca-certificates \
    curl \
    gnupg \
    file \
    binutils \
    llvm \
    lldb \
    bsdextrautils \
    xxd \
    upx-ucl \
    p7zip-full \
    squashfs-tools \
    innoextract \
    osslsigncode \
    wabt \
    binaryen \
    yara \
    strace \
    ltrace \
    gdb-multiarch \
    qemu-user \
    binwalk \
    libqt5core5t64 \
    libqt5script5 \
    python3 \
    openjdk-21-jdk-headless \
    dotnet-sdk-8.0 \
    && rm -rf /var/lib/apt/lists/*

# Install ILSpy CLI (ilspycmd 8.2.x targets .NET 8.0; 9.x+ requires .NET 9.0)
RUN dotnet tool install --tool-path /opt/dotnet-tools ilspycmd --version 8.2.0.7535 \
    && chmod -R a+rx /opt/dotnet-tools \
    && rm -rf /root/.nuget /tmp/NuGetScratch

# Install Node.js 22 LTS runtime and JS utilities
RUN mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install -g --omit=dev \
        @morluto/rea \
        @electron/asar \
        js-beautify \
        deobfuscator \
        synchrony \
    && npm cache clean --force \
    && rm -rf /var/lib/apt/lists/*

# Copy artifacts from build stages
COPY --from=downloader /opt/ghidra /opt/ghidra
COPY --from=downloader /opt/jadx /opt/jadx
COPY --from=downloader /opt/apktool /opt/apktool
COPY --from=downloader /opt/capa /opt/capa
COPY --from=downloader /opt/goresym /opt/goresym
COPY --from=downloader /opt/die/bin/diec /usr/bin/diec
COPY --from=downloader /opt/die/lib /usr/lib/die
COPY --from=downloader /opt/yara-rules /opt/yara-rules
COPY --from=cpp-builder /opt/radare2 /opt/radare2
COPY --from=cpp-builder /opt/pycdc /opt/pycdc
COPY --from=cpp-builder /opt/binhexconv /opt/binhexconv
COPY --from=cpp-builder /opt/dsp56300 /opt/dsp56300
COPY --from=python-builder /opt/re-venv /opt/re-venv

# Register Radare2 shared libraries with dynamic linker and symlink shortcuts
RUN echo "/opt/radare2/lib" > /etc/ld.so.conf.d/radare2.conf \
    && ldconfig \
    && ln -s /opt/ghidra/support/analyzeHeadless /usr/local/bin/ghidra-headless \
    && ln -s /opt/apktool/apktool /usr/local/bin/apktool \
    && ln -s /opt/capa/capa /usr/local/bin/capa \
    && ln -s /opt/goresym/GoReSym /usr/local/bin/GoReSym \
    && ln -s /opt/pycdc/bin/pycdc /usr/local/bin/pycdc \
    && ln -s /opt/pycdc/bin/pycdas /usr/local/bin/pycdas \
    && ln -s /opt/binhexconv/bin/binhexconv /usr/local/bin/binhexconv \
    && ln -s /opt/binhexconv/bin/bin2hext /usr/local/bin/bin2hext \
    && ln -s /opt/dotnet-tools/ilspycmd /usr/local/bin/ilspycmd \
    && ln -s /opt/dsp56300/bin/dsp56300-disasm /usr/local/bin/dsp56300-disasm \
    && if [ -f /opt/dsp56300/bin/dsp56300-asm ]; then ln -s /opt/dsp56300/bin/dsp56300-asm /usr/local/bin/dsp56300-asm; fi

# Make toolchains globally executable and readable, but writable only by root
RUN chmod -R a+rx /opt/radare2 /opt/ghidra /opt/jadx /opt/apktool /opt/capa /opt/goresym /opt/pycdc /opt/binhexconv /opt/dsp56300 /opt/dotnet-tools /opt/re-venv /usr/lib/die /opt/yara-rules \
    && chmod a+rx /usr/bin/diec

# Copy the MCP server script into /opt/re-mcp (mount-safe) and create unbuffered wrapper in PATH
RUN mkdir -p /opt/re-mcp /workspace/samples /workspace/output /tmp/scratch /home/ubuntu
COPY re_mcp_server.py /opt/re-mcp/re_mcp_server.py
RUN sed -i 's/\r$//' /opt/re-mcp/re_mcp_server.py \
    && chmod 755 /opt/re-mcp/re_mcp_server.py \
    && printf '#!/bin/sh\nexec /opt/re-venv/bin/python3 -u /opt/re-mcp/re_mcp_server.py "$@"\n' > /usr/local/bin/re-mcp-server \
    && chmod 755 /usr/local/bin/re-mcp-server \
    && ln -s /opt/re-mcp/re_mcp_server.py /workspace/re_mcp_server.py

# Copy custom RE aliases and append directly to skeleton .bashrc
COPY re_aliases.sh /tmp/re_aliases.sh
RUN sed -i 's/\r$//' /tmp/re_aliases.sh \
    && cat /tmp/re_aliases.sh >> /etc/skel/.bashrc \
    && rm /tmp/re_aliases.sh

# Copy entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

ENV HOME=/home/ubuntu

RUN chown -R ubuntu:ubuntu /workspace /tmp/scratch /home/ubuntu

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]
