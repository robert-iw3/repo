FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY ["CentralConsolidation.csproj", "./"]
RUN dotnet restore "CentralConsolidation.csproj"

COPY . .
RUN dotnet publish "CentralConsolidation.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

EXPOSE 8443

ENTRYPOINT ["dotnet", "CentralConsolidation.dll"]