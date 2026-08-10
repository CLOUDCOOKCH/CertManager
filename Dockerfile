FROM node:20-alpine AS web
WORKDIR /src/web
COPY src/CertificateManager.Web/package*.json ./
RUN npm install
COPY src/CertificateManager.Web/ ./
RUN npm run build
FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build
WORKDIR /src
COPY . .
COPY --from=web /src/CertificateManager.Api/wwwroot src/CertificateManager.Api/wwwroot
RUN dotnet publish src/CertificateManager.Api/CertificateManager.Api.csproj -c Release -o /app --no-self-contained
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=build --chown=app:app /app .
USER app
ENV ASPNETCORE_URLS=http://+:8080 ASPNETCORE_ENVIRONMENT=Production
EXPOSE 8080
ENTRYPOINT ["dotnet","CertificateManager.Api.dll"]
