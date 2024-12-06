# Troubleshooting

## Issue: Page Not Loaded in UI

If you navigate to `http://localhost:31548/ui` and the page does not load, there may be several potential issues. Follow these steps to troubleshoot:

1. **Check Pod Status**:  
   Ensure all relevant pods are running. You can do this by executing:  
   ```bash
   kubectl -n paladin get pods
   ```
   Look for any pods that are not in a `Running` state.

2. **Verify Service Health**:  
   Confirm that the services are healthy and accessible. Run:  
   ```bash
   kubectl -n paladin get services
   ```
   Ensure the service associated with the UI is exposed and reachable.

3. **Test Network Connectivity**:  
   Verify that the issue is not isolated to your local machine's connection to the pod. Use the following steps:
   - `exec` into another pod in the cluster and test connectivity between pods:
     ```bash
     kubectl -n paladin -it exec paladin-node2-0 -- curl http://paladin-node2:8548/ui
     ```
   - If pods fail to communicate with each other, there may be a networking issue.

4. **Check Cluster and Docker Versions**:  
   If network issues exist, you might be using an outdated version of your cluster or Docker. Ensure the following minimum versions are installed:
   - **Docker**: Version `27.0.0` or newer  
   - **Kind**: Version `0.24.0` or newer  

   You can check the versions by running:
   ```bash
   docker --version
   kind --version
   ```

If you identify an outdated version, upgrade your tools and retry.