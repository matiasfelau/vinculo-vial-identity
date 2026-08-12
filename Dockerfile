# syntax=docker/dockerfile:1

# ── Etapa de compilación ──────────────────────────────────────────────────────
# La imagen coincide con la directiva `go` del go.mod. CLAUDE.md proponía 1.22,
# pero las versiones vigentes de gin, gorm y circl exigen 1.25 como mínimo.
FROM golang:1.25-alpine AS builder

# ca-certificates se instala acá únicamente para copiar el bundle a la imagen
# final: sin él, un Postgres con sslmode=require o un broker amqps no validarían
# el certificado del servidor.
RUN apk add --no-cache ca-certificates

WORKDIR /src

# Las dependencias se copian primero para que la capa de descarga se reutilice
# mientras go.mod y go.sum no cambien.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 produce un binario estático, condición necesaria para que corra
# sobre scratch. -trimpath borra las rutas de compilación y -s -w descarta la
# tabla de símbolos: menos superficie de información y binario más chico.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/identity \
    ./cmd/api

# ── Imagen final ──────────────────────────────────────────────────────────────
# scratch: ni shell, ni gestor de paquetes, ni utilidades. Si alguien consigue
# ejecución dentro del contenedor, no encuentra con qué moverse.
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/identity /identity

# UID sin privilegios. Se expresa numéricamente porque scratch no tiene
# /etc/passwd donde resolver un nombre.
USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/identity"]
