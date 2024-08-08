import express from "express";
import { fetchAndSaveCves } from "../utils/fetchCVE.js";
import Cve from "../models/cve.models.js";

const router = express.Router();

//create cve

router.post("/", async (req, res, next) => {
  const { cpeName } = req.body;

  if (!cpeName) {
    return res.status(400).json({ message: "cpeName is required" });
  }

  try {
    await fetchAndSaveCves(cpeName);
    res.status(200).json({ message: "CVEs fetched and saved successfully" });
  } catch (error) {
    next(error);
  }
});

router.get("/", async (req, res) => {
  try {
    // Extract the page number from the query parameters, default to 1 if not provided
    const page = parseInt(req.query.page) || 1;

    // Number of CVEs to return per page
    const limit = 10;

    // Calculate the number of documents to skip based on the current page
    const skip = (page - 1) * limit;

    // Fetch the CVEs from the database, applying pagination
    const cves = await Cve.find()
      .sort({ published: -1 }) // Sort by published date, most recent first
      .skip(skip)
      .limit(limit);

    // Get the total count of CVEs in the database
    const totalCves = await Cve.countDocuments();

    // Calculate total number of pages
    const totalPages = Math.ceil(totalCves / limit);

    // Return the CVEs along with pagination info
    res.status(200).json({
      currentPage: page,
      totalPages: totalPages,
      totalCves: totalCves,
      cves: cves,
    });
  } catch (error) {
    console.error("Error fetching CVEs:", error);
    res.status(500).send("An error occurred while fetching CVEs.");
  }
});

export default router;
