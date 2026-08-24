// node-opcua server for the opcua-nse test matrix.
//
// A second, independent implementation of the protocol: where asyncua and this
// server disagree on encoding details, the NSE decoder has to cope with both.
// Offers a None endpoint plus Basic256Sha256, anonymous and user name logins,
// and the same small plant model as the asyncua servers.

const {
  OPCUAServer,
  Variant,
  DataType,
  SecurityPolicy,
  MessageSecurityMode,
  makeAccessLevelFlag,
} = require("node-opcua");

const PORT = parseInt(process.env.OPCUA_PORT || "48030", 10);

const VALID_USERS = {
  operator: "operator",
  engineer: "Password1",
};

async function main() {
  const server = new OPCUAServer({
    port: PORT,
    resourcePath: "/nse",
    buildInfo: {
      productName: "opcua-nse test server (node-opcua)",
      productUri: "urn:opcua-nse:test:node:product",
      manufacturerName: "node-opcua",
      buildNumber: "42",
      buildDate: new Date("2026-01-15T00:00:00Z"),
    },
    serverInfo: {
      applicationUri: "urn:opcua-nse:test:node",
    },
    serverCapabilities: {
      maxSessions: 20,
    },
    allowAnonymous: true,
    securityPolicies: [SecurityPolicy.None, SecurityPolicy.Basic256Sha256],
    securityModes: [MessageSecurityMode.None, MessageSecurityMode.SignAndEncrypt],
    userManager: {
      isValidUser: (username, password) => VALID_USERS[username] === password,
    },
  });

  await server.initialize();

  const addressSpace = server.engine.addressSpace;
  const namespace = addressSpace.getOwnNamespace();
  const plant = namespace.addFolder(addressSpace.rootFolder.objects, {
    browseName: "Plant",
  });

  // Three writable variables and one read-only, matching the asyncua servers,
  // so the same assertions hold for both.
  const writable = makeAccessLevelFlag("CurrentRead | CurrentWrite");
  const readOnly = makeAccessLevelFlag("CurrentRead");

  const numeric = (name, value, accessLevel) =>
    namespace.addVariable({
      componentOf: plant,
      browseName: name,
      dataType: "Double",
      accessLevel,
      userAccessLevel: accessLevel,
      value: {
        get: () => new Variant({ dataType: DataType.Double, value }),
        set: () => 0,
      },
    });

  numeric("Temperature", 20.5, writable);
  numeric("Pressure", 101.3, writable);
  numeric("Setpoint", 21.0, writable);

  namespace.addVariable({
    componentOf: plant,
    browseName: "SerialNumber",
    dataType: "String",
    accessLevel: readOnly,
    userAccessLevel: readOnly,
    value: {
      get: () => new Variant({ dataType: DataType.String, value: "SN-000042" }),
    },
  });

  namespace.addMethod(plant, {
    browseName: "Multiply",
    inputArguments: [
      { name: "x", description: "first factor", dataType: DataType.Int64 },
      { name: "y", description: "second factor", dataType: DataType.Int64 },
    ],
    outputArguments: [
      { name: "result", description: "product", dataType: DataType.Int64 },
    ],
  });

  await server.start();
  for (const endpoint of server.endpoints[0].endpointDescriptions()) {
    console.log(
      `endpoint ${endpoint.endpointUrl} mode=${MessageSecurityMode[endpoint.securityMode]} ` +
        `policy=${endpoint.securityPolicyUri}`
    );
  }
  console.log(`node-opcua server listening on port ${PORT}`);
}

main().catch((err) => {
  console.error("server failed:", err);
  process.exit(1);
});
