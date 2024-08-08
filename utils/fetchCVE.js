import axios from "axios";
import Cve from "../models/cve.models.js";

export const fetchAndLogCves = async (cpeName) => {
  try {
    const response = await axios.get(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${cpeName}`
    );
    const vulnerabilities = response.data.vulnerabilities;

    // Iterate over each vulnerability and log it to the console
    for (const vulnerability of vulnerabilities) {
      const cveData = vulnerability.cve;

      // Log the CVE data to the console
      console.log({
        id: cveData.id,
        sourceIdentifier: cveData.sourceIdentifier,
        published: cveData.published,
        lastModified: cveData.lastModified,
        vulnStatus: cveData.vulnStatus,
        cveTags: cveData.cveTags || [],
        descriptions: cveData.descriptions.map((desc) => ({
          lang: desc.lang,
          value: desc.value,
        })),
        metrics: cveData.metrics,
        weaknesses: cveData.weaknesses.map((weakness) => ({
          source: weakness.source,
          type: weakness.type,
          description: weakness.description,
        })),
        configurations: cveData.configurations.map((config) => ({
          nodes: config.nodes.map((node) => ({
            operator: node.operator,
            negate: node.negate,
            cpeMatch: node.cpeMatch.map((match) => ({
              vulnerable: match.vulnerable,
              criteria: match.criteria,
              matchCriteriaId: match.matchCriteriaId,
            })),
          })),
        })),
        references: cveData.references.map((ref) => ({
          url: ref.url,
          source: ref.source,
          tags: ref.tags,
        })),
      });
    }
  } catch (error) {
    console.error("Error fetching and logging CVEs:", error);
  }
};

export const fetchAndSaveCves = async (cpeName) => {
  try {
    const response = await axios.get(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${cpeName}`
    );
    const vulnerabilities = response.data.vulnerabilities;

    // Iterate over each vulnerability and save it to the database
    vulnerabilities.slice(0, 100).forEach(async (vulnerability) => {
      const cveData = vulnerability.cve;

      const existingCve = await Cve.findOne({ id: cveData.id });
      if (!existingCve) {
        // Create a new CVE instance using the model
        const newCve = new Cve({
          id: cveData.id,
          sourceIdentifier: cveData.sourceIdentifier,
          published: cveData.published,
          lastModified: cveData.lastModified,
          vulnStatus: cveData.vulnStatus,
          cveTags: cveData.cveTags || [],
          descriptions: cveData.descriptions.map((desc) => ({
            lang: desc.lang,
            value: desc.value,
          })),
          metrics: cveData.metrics,
          weaknesses: cveData.weaknesses.map((weakness) => ({
            source: weakness.source,
            type: weakness.type,
            description: weakness.description,
          })),
          configurations: cveData.configurations.map((config) => ({
            nodes: config.nodes.map((node) => ({
              operator: node.operator,
              negate: node.negate,
              cpeMatch: node.cpeMatch.map((match) => ({
                vulnerable: match.vulnerable,
                criteria: match.criteria,
                matchCriteriaId: match.matchCriteriaId,
              })),
            })),
          })),
          references: cveData.references.map((ref) => ({
            url: ref.url,
            source: ref.source,
            tags: ref.tags,
          })),
        });

        // Save the new CVE document to the database
        await newCve.save();
      }
    });
  } catch (error) {
    console.error("Error fetching and saving CVEs:", error);
  }
};
