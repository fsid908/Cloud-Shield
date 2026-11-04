
import fileMonitor from "./fileMonitor.service.js";

const getHealthStatus = () => {
  return {
    status: "OK",
    message: "Server is running smoothly",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
    monitoring: fileMonitor.getStatus(),
  };
};

export default {
  getHealthStatus,
};
