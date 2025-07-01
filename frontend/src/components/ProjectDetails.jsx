// File: src/components/ProjectDetails.js
import React, { useState, useEffect, useRef } from "react";
import { useParams, Link } from "react-router-dom";

import api from "../services/api";
import Navbar from "./Navbar";

const ProjectDetails = () => {
  const { projectId } = useParams();
  const [project, setProject] = useState(null);
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [uploading, setUploading] = useState(false);
  const [committing, setCommitting] = useState(false);
  const fileInputRef = useRef(null);

  const [commits, setCommits] = useState([]);
  const [loadingCommits, setLoadingCommits] = useState(false);
  const [rollbackInProgress, setRollbackInProgress] = useState(false);

  const [accessRequests, setAccessRequests] = useState([]);
  const [loadingRequests, setLoadingRequests] = useState(false);
  const [processingRequest, setProcessingRequest] = useState(false);

  // const [currentUser, setCurrentUser] = useState(null)
  const [currentUser, setCurrentUser] = useState(null);

  // New state for branches and merge requests
  const [branches, setBranches] = useState([]);
  const [loadingBranches, setLoadingBranches] = useState(false);
  const [mergeRequests, setMergeRequests] = useState([]);
  const [loadingMergeRequests, setLoadingMergeRequests] = useState(false);
  const [newBranchName, setNewBranchName] = useState("");
  const [showNewBranchForm, setShowNewBranchForm] = useState(false);
  const [creatingBranch, setCreatingBranch] = useState(false);
  const [selectedMergeRequest, setSelectedMergeRequest] = useState(null);
  const [diffData, setDiffData] = useState(null);
  const [loadingDiff, setLoadingDiff] = useState(false);
  const [processingMerge, setProcessingMerge] = useState(false);
  const [checkingOutBranch, setCheckingOutBranch] = useState(false);
  const [currentBranch, setCurrentBranch] = useState("master"); // Add state for current branch
  const [successMessage, setSuccessMessage] = useState(null);

  const [threatScanning, setThreatScanning] = useState(false);
  const [threatResults, setThreatResults] = useState(null);
  const [showThreatModal, setShowThreatModal] = useState(false);
  const [pendingFiles, setPendingFiles] = useState(null);
  const [commitPending, setCommitPending] = useState(false);

  useEffect(() => {
    const fetchProjectDetails = async () => {
      try {
        setLoading(true);
        const projectResponse = await api.get(`/projects/${projectId}`);
        setProject(projectResponse.data);
  
        const filesResponse = await api.get(`/projects/${projectId}/files`);
        setFiles(filesResponse.data);
  
        // Get current branch from server
        try {
          const branchResponse = await api.get(`/projects/${projectId}/current-branch`);
          if (branchResponse.data && branchResponse.data.currentBranch) {
            setCurrentBranch(branchResponse.data.currentBranch);
          } else {
            // Default to 'master' or 'main' if no current branch is found
            setCurrentBranch('master');
          }
        } catch (branchErr) {
          console.error("Failed to fetch current branch:", branchErr);
          setCurrentBranch('master'); // Fallback to a default branch
        }
  
        // Get current user info and save it to state
        const userResponse = await api.get("/users/me");
        const user = userResponse.data;
        setCurrentUser(user);
  
        // If user is the project owner, fetch access requests
        if (projectResponse.data.user_id === user._id) {
          fetchAccessRequests();
          fetchMergeRequests();
        }
        fetchBranches();
      } catch (err) {
        setError("Failed to fetch project details");
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
  
    fetchProjectDetails();
  }, [projectId]);

  const fetchBranches = async () => {
    try {
      setLoadingBranches(true);
      const response = await api.get(`/projects/${projectId}/branches`);
      setBranches(response.data.branches);
    } catch (err) {
      console.error("Failed to fetch branches:", err);
    } finally {
      setLoadingBranches(false);
    }
  };

  const fetchMergeRequests = async () => {
    try {
      setLoadingMergeRequests(true);
      const response = await api.get(`/projects/${projectId}/merge-requests`);
      setMergeRequests(response.data.mergeRequests);
    } catch (err) {
      console.error("Failed to fetch merge requests:", err);
    } finally {
      setLoadingMergeRequests(false);
    }
  };

  const handleCreateBranch = async (e) => {
    e.preventDefault();
    if (!newBranchName.trim()) return;

    try {
      setCreatingBranch(true);
      const response = await api.post(`/projects/${projectId}/branches`, {
        branchName: newBranchName,
      });

      // Get the branch name from the response (important for user branches which get prefixed)
      const createdBranchName = response.data.branchName || newBranchName;

      setNewBranchName("");
      setShowNewBranchForm(false);
      await fetchBranches();

      // Optionally checkout the newly created branch
      if (
        window.confirm(
          `Branch created successfully. Do you want to check out "${createdBranchName}" now?`
        )
      ) {
        await handleCheckoutBranch(createdBranchName);
      }
    } catch (err) {
      setError(
        "Failed to create branch: " +
          (err.response?.data?.message || err.message)
      );
    } finally {
      setCreatingBranch(false);
    }
  };

  const handleCheckoutBranch = async (branchName) => {
    try {
      setCheckingOutBranch(true);
      await api.post(
        `/projects/${projectId}/branches/${encodeURIComponent(
          branchName
        )}/checkout`
      );
  
      // Update current branch state
      setCurrentBranch(branchName);
  
      // Refresh files list after checkout
      const filesResponse = await api.get(`/projects/${projectId}/files`);
      setFiles(filesResponse.data);
  
      // Show success message
      setSuccessMessage(`Successfully checked out branch: ${branchName}`);
  
      // Clear success message after a few seconds
      setTimeout(() => setSuccessMessage(""), 3000);
    } catch (err) {
      setError(
        "Failed to checkout branch: " +
          (err.response?.data?.message || err.message)
      );
    } finally {
      setCheckingOutBranch(false);
    }
  };

  const handleCreateMergeRequest = async (branchName) => {
    try {
      await api.post(`/projects/${projectId}/merge-requests`, {
        sourceBranch: branchName,
      });
      setError(""); // Clear any existing errors
      alert("Merge request created successfully");
    } catch (err) {
      setError(
        "Failed to create merge request: " +
          (err.response?.data?.message || err.message)
      );
    }
  };

  const viewMergeRequestDiff = async (requestId) => {
    try {
      setLoadingDiff(true);
      const response = await api.get(
        `/projects/${projectId}/merge-requests/${requestId}/diff`
      );
      setDiffData(response.data.diff);
      setSelectedMergeRequest(requestId);
    } catch (err) {
      setError(
        "Failed to load diff: " + (err.response?.data?.message || err.message)
      );
    } finally {
      setLoadingDiff(false);
    }
  };

  const handleMergeRequestAction = async (requestId, approve) => {
    try {
      setProcessingMerge(true);
      const endpoint = approve ? "approve" : "reject";
      await api.post(
        `/projects/${projectId}/merge-requests/${requestId}/${endpoint}`
      );

      // Refresh merge requests list and branches
      await fetchMergeRequests();
      await fetchBranches();
      // Clear selected merge request and diff data
      setSelectedMergeRequest(null);
      setDiffData(null);

      // Refresh files list if approved
      if (approve) {
        const filesResponse = await api.get(`/projects/${projectId}/files`);
        setFiles(filesResponse.data);
      }
    } catch (err) {
      setError(
        "Failed to process merge request: " +
          (err.response?.data?.message || err.message)
      );
    } finally {
      setProcessingMerge(false);
    }
  };

  const fetchAccessRequests = async () => {
    try {
      setLoadingRequests(true);
      const response = await api.get(`/projects/${projectId}/access-requests`);
      setAccessRequests(response.data.requests);
    } catch (err) {
      console.error("Failed to fetch access requests:", err);
    } finally {
      setLoadingRequests(false);
    }
  };

  const handleAccessRequest = async (userId, approve) => {
    try {
      setProcessingRequest(true);
      await api.put(`/projects/${projectId}/access-requests/${userId}`, {
        approve,
      });

      // Update the list after processing
      await fetchAccessRequests();
    } catch (err) {
      setError("Failed to process access request");
    } finally {
      setProcessingRequest(false);
    }
  };

  // Modify the handleFileUpload function to include threat checking
  const handleFileUpload = async (e) => {
    const files = e.target.files;
    if (!files.length) return;

    const formData = new FormData();
    Array.from(files).forEach((file) => {
      formData.append("files", file);
    });

    try {
      setUploading(true);

      // Check for threats before actual upload
      const canProceed = await checkUploadedFilesForThreats(formData);

      if (canProceed) {
        // Proceed with the actual upload
        await api.post(`/projects/${projectId}/upload`, formData, {
          headers: {
            "Content-Type": "multipart/form-data",
          },
        });

        // Refresh files list
        const filesResponse = await api.get(`/projects/${projectId}/files`);
        setFiles(filesResponse.data);
      }
    } catch (err) {
      setError("File upload failed");
    } finally {
      setUploading(false);
      e.target.value = ""; // Clear file input
    }
  };
  // Modify the handleCommit function to include threat checking
  const handleCommit = async () => {
    try {
      setCommitting(true);

      // Check for threats before committing
      const canProceed = await checkForThreatsBeforeCommit();

      if (canProceed) {
        await api.post(`/projects/${projectId}/commit`);
        setError("");

        // Refresh commit history after committing
        await fetchCommitHistory();
      }
    } catch (err) {
      setError(err.response?.data?.message || "Commit failed");
    } finally {
      setCommitting(false);
    }
  };

  const fetchCommitHistory = async () => {
    try {
      setLoadingCommits(true);
      const response = await api.get(`/projects/${projectId}/commits`);
      setCommits(response.data.commits);
    } catch (err) {
      console.error("Failed to fetch commit history:", err);
    } finally {
      setLoadingCommits(false);
    }
  };

  useEffect(() => {
    fetchCommitHistory();
  }, [projectId]);

  const handleRollback = async (commitId) => {
    if (
      window.confirm(
        "Are you sure you want to rollback to this commit? All changes since then will be lost."
      )
    ) {
      try {
        setRollbackInProgress(true);
        await api.post(`/projects/${projectId}/rollback/${commitId}`);

        // Refresh the file list and commits after rollback
        const filesResponse = await api.get(`/projects/${projectId}/files`);
        setFiles(filesResponse.data);
        await fetchCommitHistory();
      } catch (err) {
        setError("Rollback failed");
        console.error(err);
      } finally {
        setRollbackInProgress(false);
      }
    }
  };

  const checkUploadedFilesForThreats = async (formData) => {
    try {
      setThreatScanning(true);

      // First upload files to a temporary location
      const tempUploadResponse = await api.post(
        `/projects/${projectId}/temp-upload`,
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
          },
        }
      );

      // Then scan the files
      const threatResponse = await api.get(
        `/projects/${projectId}/threat-check`
      );
      setThreatResults(threatResponse.data);

      // If there are serious threats, show modal
      if (threatResponse.data.total_threats > 0) {
        // Check for serious threats (everything except Threat Actor References)
        const seriousThreats = threatResponse.data.results.some((result) =>
          result.threats.some(
            (threat) => threat.type !== "Threat Actor Reference"
          )
        );

        if (seriousThreats) {
          setPendingFiles(formData);
          setShowThreatModal(true);
          return false;
        }
      }

      return true; // No serious threats found
    } catch (err) {
      setError("Failed to check files for threats");
      console.error(err);
      return false;
    } finally {
      setThreatScanning(false);
    }
  };

  const checkForThreatsBeforeCommit = async () => {
    try {
      setThreatScanning(true);

      const threatResponse = await api.get(
        `/projects/${projectId}/threat-check`
      );
      setThreatResults(threatResponse.data);

      // If there are serious threats, show modal
      if (threatResponse.data.total_threats > 0) {
        // Check for serious threats (everything except Threat Actor References)
        const seriousThreats = threatResponse.data.results.some((result) =>
          result.threats.some(
            (threat) => threat.type !== "Threat Actor Reference"
          )
        );

        if (seriousThreats) {
          setCommitPending(true);
          setShowThreatModal(true);
          return false;
        }
      }

      return true; // No serious threats found
    } catch (err) {
      setError("Failed to check files for threats");
      console.error(err);
      return false;
    } finally {
      setThreatScanning(false);
    }
  };

  // Add this function to handle force upload when the user wants to proceed despite threats
  const handleForceUpload = async () => {
    try {
      setUploading(true);

      // Proceed with the actual upload using the pending files
      await api.post(`/projects/${projectId}/upload`, pendingFiles, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });

      // Refresh files list
      const filesResponse = await api.get(`/projects/${projectId}/files`);
      setFiles(filesResponse.data);

      // Close the modal and reset
      setShowThreatModal(false);
      setPendingFiles(null);
    } catch (err) {
      setError("File upload failed");
    } finally {
      setUploading(false);
    }
  };

  // Add this function to handle force commit when the user wants to proceed despite threats
  const handleForceCommit = async () => {
    try {
      setCommitting(true);

      await api.post(`/projects/${projectId}/commit`);
      setError("");

      // Refresh commit history after committing
      await fetchCommitHistory();

      // Close the modal and reset
      setShowThreatModal(false);
      setCommitPending(false);
    } catch (err) {
      setError(err.response?.data?.message || "Commit failed");
    } finally {
      setCommitting(false);
    }
  };

  // Add this function to cancel upload/commit
  const handleCancel = () => {
    setShowThreatModal(false);
    setPendingFiles(null);
    setCommitPending(false);
  };

  // Add the threat modal component to your return statement
  const ThreatModal = () => {
    if (!showThreatModal) return null;

    return (
      <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex items-center justify-center">
        <div className="bg-white p-5 rounded-md w-full max-w-md mx-auto">
          <h3 className="text-lg font-bold text-red-600 mb-3">
            ⚠️ Security Alert
          </h3>
          <p className="mb-4">
            Threat intelligence has detected potentially harmful content in your
            files:
          </p>

          {threatResults && threatResults.results.length > 0 && (
            <div className="max-h-64 overflow-y-auto mb-4 border rounded">
              {threatResults.results.map((result, idx) => (
                <div key={idx} className="p-2 border-b last:border-b-0">
                  <div className="font-medium text-sm">{result.filename}</div>
                  <ul className="mt-1">
                    {result.threats.map((threat, tidx) => (
                      <li key={tidx} className="text-xs flex items-center py-1">
                      <span
                        className={`inline-block px-1 rounded text-white mr-1 ${
                          threat.type === "Vulnerability"
                            ? "bg-red-600"
                            : threat.type === "Malicious IP"
                            ? "bg-orange-500"
                            : threat.type === "IOC"
                            ? "bg-purple-500"
                            : threat.type === "Hardcoded Credential"
                            ? "bg-pink-600"
                            : threat.type === "XSS Vulnerability" 
                            ? "bg-yellow-600"
                            : threat.type === "SQL Injection"
                            ? "bg-red-800"
                            : "bg-blue-500"
                        }`}
                      >
                        {threat.type}
                      </span>
                      <span>{threat.indicator}</span>
                      {threat.severity && (
                        <span
                          className={`ml-1 text-xs px-1 rounded ${
                            threat.severity === "CRITICAL"
                              ? "bg-red-100 text-red-800"
                              : threat.severity === "HIGH"
                              ? "bg-orange-100 text-orange-800"
                              : threat.severity === "MEDIUM"
                              ? "bg-yellow-100 text-yellow-800"
                              : "bg-blue-100 text-blue-800"
                          }`}
                        >
                          {threat.severity}
                        </span>
                      )}
                    </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          )}

          <p className="text-sm text-gray-700 mb-4">
            This file contains potentially malicious code that could pose
            security risks. We recommend reviewing the file carefully before
            proceeding.
          </p>

          <div className="flex justify-end space-x-3">
            <button
              onClick={handleCancel}
              className="px-4 py-2 bg-gray-300 hover:bg-gray-400 rounded"
            >
              Cancel
            </button>
            <button
              onClick={commitPending ? handleForceCommit : handleForceUpload}
              className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded"
            >
              Proceed Anyway
            </button>
          </div>
        </div>
      </div>
    );
  };













  const fetchCurrentBranch = async () => {
    try {
      const response = await api.get(`/projects/${projectId}/current-branch`);
      if (response.data && response.data.currentBranch) {
        setCurrentBranch(response.data.currentBranch);
      }
    } catch (err) {
      console.error("Failed to fetch current branch:", err);
    }
  };












  // Add this component to display threat results after upload/commit
  const ThreatResultsDisplay = () => {
    if (!threatResults) return null;

    return (
      <div className="mt-4 border-t pt-4">
        <h3 className="font-medium mb-2">Threat Scan Results</h3>
        <div
          className={`px-3 py-2 rounded mb-2 text-sm ${
            threatResults.total_threats > 0
              ? "bg-red-100 text-red-800"
              : "bg-green-100 text-green-800"
          }`}
        >
          <div className="font-medium">
            {threatResults.total_threats > 0
              ? `⚠️ ${threatResults.total_threats} threat${
                  threatResults.total_threats !== 1 ? "s" : ""
                } found`
              : "✅ No threats found"}
          </div>
          <div className="text-xs mt-1">
            Scanned {threatResults.files_scanned} file
            {threatResults.files_scanned !== 1 ? "s" : ""}
          </div>
        </div>

        {threatResults.results.length > 0 && (
          <div className="mt-2 max-h-48 overflow-y-auto">
            {threatResults.results.map((result, idx) => (
              <div
                key={idx}
                className="mb-2 bg-gray-50 p-2 rounded border border-gray-200"
              >
                <div className="font-medium text-sm truncate">
                  {result.filename}
                </div>
                <ul className="mt-1">
                  {result.threats.map((threat, tidx) => (
                   <li
                   key={tidx}
                   className="text-xs py-1 border-t border-gray-100"
                 >
                   <span
                     className={`inline-block px-1 rounded text-white mr-1 ${
                       threat.type === "Vulnerability"
                         ? "bg-red-600"
                         : threat.type === "Malicious IP"
                         ? "bg-orange-500"
                         : threat.type === "IOC"
                         ? "bg-purple-500"
                         : threat.type === "Hardcoded Credential"
                         ? "bg-pink-600"
                         : threat.type === "XSS Vulnerability" 
                         ? "bg-yellow-600"
                         : threat.type === "SQL Injection"
                         ? "bg-red-800"
                         : "bg-blue-500"
                     }`}
                   >
                     {threat.type}
                   </span>
                   <span className="font-medium">{threat.indicator}</span>
                   {threat.severity && (
                     <span
                       className={`ml-1 text-xs px-1 rounded ${
                         threat.severity === "CRITICAL"
                           ? "bg-red-100 text-red-800"
                           : threat.severity === "HIGH"
                           ? "bg-orange-100 text-orange-800"
                           : threat.severity === "MEDIUM"
                           ? "bg-yellow-100 text-yellow-800"
                           : "bg-blue-100 text-blue-800"
                       }`}
                     >
                       {threat.severity}
                     </span>
                   )}
                   {threat.cvss_score && (
                     <span className="ml-1">({threat.cvss_score})</span>
                   )}
                 </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  // Filter branches that belong to the current user
  const getUserBranches = () => {
    if (!currentUser) return [];
    return branches.filter(
      (branch) =>
        branch.name.startsWith(`user_${currentUser._id}`) ||
        branch.name === "master"
    );
  };

  // Check if user can create branches
  const canCreateBranch = () => {
    if (!project || !currentUser) return false;
    return project.isPublic || project.user_id === currentUser._id;
  };

  const canCreateMergeRequest = (branchName) => {
    if (!project || !currentUser) return false;
    if (project.user_id === currentUser._id) return false; // Owner doesn't need merge requests
    if (!project.isPublic) return false; // Only public projects support merge requests

    // Can only create merge requests from your own branches
    return branchName.startsWith(`user_${currentUser._id}`);
  };
  if (loading) {
    return (
      <div>
        <Navbar />
        <div className="container mx-auto p-4">
          <div className="flex items-center justify-center h-64">
            <p>Loading project details...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <Navbar />
        <div className="container mx-auto p-4">
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
            {error}
          </div>
          <Link to="/dashboard" className="text-blue-600 hover:text-blue-800">
            &larr; Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  if (!project) {
    return (
      <div>
        <Navbar />
        <div className="container mx-auto p-4">
          <div className="bg-yellow-100 border border-yellow-400 text-yellow-700 px-4 py-3 rounded mb-4">
            Project not found or you don't have permission to view it.
          </div>
          <Link to="/dashboard" className="text-blue-600 hover:text-blue-800">
            &larr; Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }
  return (
    <div>
      <Navbar />
      <div className="container mx-auto p-4">
        <div className="flex items-center justify-between mb-6">
          <div>
            <Link to="/dashboard" className="text-blue-600 hover:text-blue-800">
              &larr; Back to Dashboard
            </Link>
            <h1 className="text-2xl font-bold mt-2">{project.name}</h1>
            <p className="text-gray-500">
              {project.isPublic ? "Public" : "Private"} • Created:{" "}
              {new Date(project.createdAt).toLocaleDateString()}
            </p>
          </div>
        </div>

        <div className="bg-white p-6 rounded shadow-md">
          {/* Branch Management Section */}
          <div className="mb-8">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-semibold">Branches</h2>
              {canCreateBranch() && (
                <button
                  onClick={() => setShowNewBranchForm(!showNewBranchForm)}
                  className="bg-blue-500 hover:bg-blue-600 text-white px-3 py-1 rounded text-sm"
                >
                  {showNewBranchForm ? "Cancel" : "Create Branch"}
                </button>
              )}
            </div>

            {/* Success/Error Messages */}
            {successMessage && (
              <div className="mb-4 p-3 bg-green-100 border border-green-400 text-green-700 rounded">
                {successMessage}
              </div>
            )}

            {error && (
              <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
                {error}
              </div>
            )}

            {showNewBranchForm && (
              <form
                onSubmit={handleCreateBranch}
                className="mb-4 p-4 bg-gray-50 rounded"
              >
                <div className="flex items-center">
                  <input
                    type="text"
                    value={newBranchName}
                    onChange={(e) => setNewBranchName(e.target.value)}
                    placeholder="Branch name"
                    className="flex-1 border p-2 rounded-l"
                    required
                  />
                  <button
                    type="submit"
                    disabled={creatingBranch}
                    className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-r disabled:opacity-50"
                  >
                    {creatingBranch ? "Creating..." : "Create"}
                  </button>
                </div>
                <p className="text-sm text-gray-500 mt-2">
                  {project.isPublic && currentUser?._id !== project.user_id
                    ? "This will create a personal branch visible only to you."
                    : "This will create a new branch from the current HEAD."}
                </p>
                <p className="text-sm text-red-500 mt-1">
                  Note: Repository must have at least one commit before creating
                  a branch.
                </p>
              </form>
            )}

            {loadingBranches ? (
              <div className="text-center py-4">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto"></div>
                <p className="mt-2">Loading branches...</p>
              </div>
            ) : branches.length === 0 ? (
              <div className="p-4 bg-yellow-50 border border-yellow-200 rounded text-yellow-800">
                <p>
                  No branches found in this project. You may need to make an
                  initial commit first.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto border rounded">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Branch Name
                      </th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Last Commit
                      </th>
                      <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {/* Only show branches the user should see */}
                    {(project.user_id === currentUser?._id
                      ? branches
                      : getUserBranches()
                    ).map((branch) => (
                      <tr
                        key={branch.name}
                        className={
                          currentBranch === branch.name ? "bg-blue-50" : ""
                        }
                      >
                        <td className="px-4 py-2 whitespace-nowrap">
                          <div className="flex items-center">
                            {currentBranch === branch.name && (
                              <span className="mr-2 text-blue-500">
                                <svg
                                  xmlns="http://www.w3.org/2000/svg"
                                  className="h-4 w-4"
                                  fill="none"
                                  viewBox="0 0 24 24"
                                  stroke="currentColor"
                                >
                                  <path
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                    strokeWidth={2}
                                    d="M5 13l4 4L19 7"
                                  />
                                </svg>
                              </span>
                            )}
                            <span
                              className={
                                currentBranch === branch.name
                                  ? "font-medium text-blue-600"
                                  : ""
                              }
                            >
                              {branch.name}
                            </span>
                            {currentBranch === branch.name && (
                              <span className="ml-2 text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded-full">
                                Current
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-2">
                          <div className="text-sm">
                            {branch.lastCommit.message}
                          </div>
                          <div className="text-xs text-gray-500">
                            {branch.lastCommit.author} •{" "}
                            {new Date(
                              branch.lastCommit.date * 1000
                            ).toLocaleString()}
                          </div>
                        </td>
                        <td className="px-4 py-2 whitespace-nowrap text-right text-sm">
                          {currentBranch !== branch.name ? (
                            <button
                              onClick={() => handleCheckoutBranch(branch.name)}
                              disabled={checkingOutBranch}
                              className="text-blue-600 hover:text-blue-800 mr-3 disabled:opacity-50"
                            >
                              {checkingOutBranch
                                ? "Checking out..."
                                : "Checkout"}
                            </button>
                          ) : (
                            <span className="text-gray-500 mr-3">
                              Checked Out
                            </span>
                          )}

                          {canCreateMergeRequest(branch.name) && (
                            <button
                              onClick={() =>
                                handleCreateMergeRequest(branch.name)
                              }
                              className="text-green-600 hover:text-green-800"
                            >
                              Create Merge Request
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Current branch indicator */}
            <div className="mt-3 text-sm text-gray-600">
              <strong>Current branch:</strong> {currentBranch}
            </div>
          </div>
        </div>

        {/* Merge Requests Section - Only visible to project owner */}
        {project.user_id === currentUser?._id && (
          <div className="mb-8">
            <h2 className="text-xl font-semibold mt-4 mb-4">Merge Requests</h2>

            {loadingMergeRequests ? (
              <p>Loading merge requests...</p>
            ) : mergeRequests.length === 0 ? (
              <p className="text-gray-500">No pending merge requests</p>
            ) : (
              <div className="space-y-4">
                {mergeRequests.map((request) => (
                  <div key={request.id} className="border rounded p-4">
                    <div className="flex justify-between items-center mb-3">
                      <div>
                        <h3 className="font-medium">
                          {request.source_branch} → {request.target_branch}
                        </h3>
                        <p className="text-sm text-gray-500">
                          Requested by {request.requester.name} •{" "}
                          {new Date(request.created_at).toLocaleString()}
                        </p>
                      </div>
                      <div className="flex space-x-2">
                        {!selectedMergeRequest ||
                        selectedMergeRequest !== request.id ? (
                          <button
                            onClick={() => viewMergeRequestDiff(request.id)}
                            disabled={loadingDiff}
                            className="bg-blue-500 hover:bg-blue-600 text-white px-3 py-1 text-sm rounded disabled:opacity-50"
                          >
                            {loadingDiff && selectedMergeRequest === request.id
                              ? "Loading..."
                              : "View Changes"}
                          </button>
                        ) : (
                          <button
                            onClick={() => {
                              setSelectedMergeRequest(null);
                              setDiffData(null);
                            }}
                            className="bg-gray-500 hover:bg-gray-600 text-white px-3 py-1 text-sm rounded"
                          >
                            Hide Changes
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Show diff data if this merge request is selected */}
                    {selectedMergeRequest === request.id && diffData && (
                      <div className="mt-3 p-3 bg-gray-50 rounded border">
                        <div className="mb-2 text-sm font-medium">
                          Changes: {diffData.stats.files_changed} files changed,{" "}
                          {diffData.stats.insertions} insertions,{" "}
                          {diffData.stats.deletions} deletions
                        </div>

                        <div className="space-y-3">
                          {diffData.files_changed.map((file, index) => (
                            <div
                              key={index}
                              className="border rounded overflow-hidden"
                            >
                              <div className="bg-gray-100 p-2 border-b flex justify-between">
                                <span className="font-mono text-sm">
                                  {file.status === "A" && "+ Added: "}
                                  {file.status === "M" && "~ Modified: "}
                                  {file.status === "D" && "- Deleted: "}
                                  {file.new_file}
                                </span>
                                <span
                                  className={`text-xs px-2 py-1 rounded ${
                                    file.status === "A"
                                      ? "bg-green-100 text-green-700"
                                      : file.status === "D"
                                      ? "bg-red-100 text-red-700"
                                      : "bg-yellow-100 text-yellow-700"
                                  }`}
                                >
                                  {file.status === "A"
                                    ? "Added"
                                    : file.status === "D"
                                    ? "Deleted"
                                    : "Modified"}
                                </span>
                              </div>

                              {!file.is_binary && file.patch ? (
                                <pre className="p-2 overflow-x-auto text-xs font-mono bg-white max-h-60 overflow-y-auto">
                                  {file.patch}
                                </pre>
                              ) : (
                                <div className="p-2 text-sm text-gray-500">
                                  {file.is_binary
                                    ? "Binary file not shown"
                                    : "No changes"}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>

                        <div className="mt-4 flex justify-end space-x-3">
                          <button
                            onClick={() =>
                              handleMergeRequestAction(request.id, false)
                            }
                            disabled={processingMerge}
                            className="bg-red-500 hover:bg-red-600 text-white px-3 py-1 text-sm rounded disabled:opacity-50"
                          >
                            {processingMerge ? "Processing..." : "Reject"}
                          </button>
                          <button
                            onClick={() => {
                              if (
                                window.confirm(
                                  "Are you sure you want to approve this merge request?"
                                )
                              ) {
                                handleMergeRequestAction(request.id, true);
                              }
                            }}
                            disabled={processingMerge}
                            className="bg-green-500 hover:bg-green-600 text-white px-3 py-1 text-sm rounded disabled:opacity-50"
                          >
                            {processingMerge
                              ? "Processing..."
                              : "Approve & Merge"}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
{/* Add this to your JSX where you want the Threat Modal to appear */}
<ThreatModal />

{/* Update your project files display section JSX */}
<div className="flex justify-between items-center mb-4">
  <h2 className="text-xl font-semibold">Project Files</h2>
  <div className="space-x-4">
    <input
      type="file"
      multiple
      ref={fileInputRef}
      onChange={handleFileUpload}
      className="hidden"
    />
    <button
      onClick={() => fileInputRef.current.click()}
      disabled={uploading || threatScanning}
      className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded disabled:opacity-50"
    >
      {uploading ? "Uploading..." : threatScanning ? "Scanning..." : "Add from Local Storage"}
    </button>
    <button
      onClick={handleCommit}
      disabled={committing || threatScanning}
      className="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded disabled:opacity-50"
    >
      {committing ? "Committing..." : threatScanning ? "Scanning..." : "Commit Changes"}
    </button>
    <Link
      to={`/projects/${projectId}/ide`}
      className="bg-purple-500 hover:bg-purple-600 text-white px-4 py-2 rounded inline-block"
    >
      Open in IDE
    </Link>
  </div>
</div>

{/* Display threat results if available */}
{threatResults && <ThreatResultsDisplay />}

{files.length === 0 ? (
  <p>No files found in this project.</p>
) : (
  <div className="space-y-2">
    {files.map((file) => (
      <div
        key={file.name}
        className="border rounded p-3 flex justify-between items-center"
      >
        <div className="flex items-center">
          <svg
            className="w-5 h-5 text-gray-500 mr-2"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            ></path>
          </svg>
          <span>{file.name}</span>
        </div>
        <span className="text-sm text-gray-500">
          {file.size} bytes • Last modified:{" "}
          {new Date(file.lastModified).toLocaleDateString()}
        </span>
      </div>
    ))}
  </div>
)}


{/* Add a manual threat check button */}
{project && project?.user_id === currentUser?._id && (
  <div className="mt-4">
    <button
      onClick={() => checkForThreatsBeforeCommit()}
      disabled={threatScanning}
      className="bg-yellow-500 hover:bg-yellow-600 text-white px-3 py-1 rounded text-sm flex items-center"
    >
      {threatScanning ? (
        <span className="flex items-center">
          <svg
            className="animate-spin -ml-1 mr-2 h-4 w-4 text-white"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            ></circle>
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            ></path>
          </svg>
          Scanning...
        </span>
      ) : (
        <>
          <svg
            className="w-4 h-4 mr-2"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
            ></path>
          </svg>
          Threat Intelligence Check
        </>
      )}
    </button>
  </div>
)}
        {/* Add this commit history section */}
        <div className="mt-8 mb-4">
          <h3 className="text-lg font-semibold mb-2">Commit History</h3>

          {loadingCommits ? (
            <p>Loading commit history...</p>
          ) : commits.length === 0 ? (
            <p>No commits found for this project.</p>
          ) : (
            <div className="border rounded overflow-hidden">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Message
                    </th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Author
                    </th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Date
                    </th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Action
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {commits.map((commit) => (
                    <tr key={commit.id}>
                      <td className="px-4 py-2 whitespace-nowrap">
                        {commit.message}
                      </td>
                      <td className="px-4 py-2 whitespace-nowrap">
                        {commit.author}
                      </td>
                      <td className="px-4 py-2 whitespace-nowrap">
                        {new Date(commit.date * 1000).toLocaleString()}
                      </td>
                      <td className="px-4 py-2 whitespace-nowrap text-right">
                        <button
                          onClick={() => handleRollback(commit.id)}
                          disabled={rollbackInProgress}
                          className="text-blue-600 hover:text-blue-800 disabled:text-gray-400"
                        >
                          {rollbackInProgress ? "Rolling back..." : "Rollback"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="mt-6 text-sm text-gray-500">
          <p>
            Note: Files can be manually added to the project folder on the
            server and through upload.
          </p>
        </div>

        {project && project.user_id === currentUser._id && (
          <div className="mt-6 border-t pt-6">
            <h3 className="text-lg font-semibold mb-4">Access Requests</h3>

            {loadingRequests ? (
              <p>Loading access requests...</p>
            ) : accessRequests.length === 0 ? (
              <p className="text-gray-500">No pending access requests</p>
            ) : (
              <div className="space-y-4">
                {accessRequests.map((user) => (
                  <div
                    key={user._id}
                    className="border p-4 rounded flex justify-between items-center"
                  >
                    <div>
                      <p className="font-medium">{user.name}</p>
                      <p className="text-gray-500 text-sm">{user.email}</p>
                    </div>
                    <div className="space-x-2">
                      <button
                        onClick={() => handleAccessRequest(user._id, true)}
                        disabled={processingRequest}
                        className="bg-green-500 hover:bg-green-600 text-white px-3 py-1 text-sm rounded disabled:opacity-50"
                      >
                        Approve
                      </button>
                      <button
                        onClick={() => handleAccessRequest(user._id, false)}
                        disabled={processingRequest}
                        className="bg-red-500 hover:bg-red-600 text-white px-3 py-1 text-sm rounded disabled:opacity-50"
                      >
                        Deny
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ProjectDetails;
