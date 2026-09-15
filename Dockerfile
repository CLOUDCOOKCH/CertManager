FROM node:20-alpine AS web
WORKDIR /src/web
COPY src/CertificateManager.Web/package*.json ./
RUN npm install --include=dev
COPY src/CertificateManager.Web/ ./
RUN npm run build -- --outDir /web-dist

FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build
WORKDIR /src
COPY CertificateManager.sln ./
COPY src/CertificateManager.Domain/CertificateManager.Domain.csproj src/CertificateManager.Domain/
COPY src/CertificateManager.Application/CertificateManager.Application.csproj src/CertificateManager.Application/
COPY src/CertificateManager.Infrastructure/CertificateManager.Infrastructure.csproj src/CertificateManager.Infrastructure/
COPY src/CertificateManager.Api/CertificateManager.Api.csproj src/CertificateManager.Api/
RUN dotnet restore src/CertificateManager.Api/CertificateManager.Api.csproj
COPY src/ src/
COPY --from=web /web-dist/ src/CertificateManager.Api/wwwroot/
RUN dotnet publish src/CertificateManager.Api/CertificateManager.Api.csproj -c Release -o /app --no-restore --no-self-contained

FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine
WORKDIR /app
COPY --from=build --chown=app:app /app .
RUN mkdir -p /app/keys && chown app:app /app/keys
USER app
ENV ASPNETCORE_URLS=http://+:8080 ASPNETCORE_ENVIRONMENT=Production
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/api/health || exit 1
ENTRYPOINT ["dotnet","CertificateManager.Api.dll"]
