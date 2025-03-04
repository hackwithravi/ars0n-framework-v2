import React from 'react';
import { Accordion, ListGroup } from 'react-bootstrap';

const HelpMeLearn = ({ section }) => {
  const sections = {
    amass: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and what are we trying to accomplish?",
          answers: [
            "This workflow is part of the Reconnaissance (Recon) phase of the Bug Bounty Hunting methodology.",
            "We have identified a root domain that belongs to the target organization. Now our goal is to find a list of subdomains for that root domain that point to a live web server. Each live web server is a possible target for bug bounty testing. At the end of this workflow, we will have a list of Target URLs that can be added as \"URL\" Scope Targets."
          ]
        },
        {
          question: "What is Amass and how does it work?",
          answers: [
            "Amass is a powerful open-source tool for performing attack surface mapping and external asset discovery. It uses various techniques including DNS enumeration, web scraping, and data source integration to build a comprehensive map of an organization's external attack surface.",
            "The tool works by combining multiple data sources and techniques: DNS enumeration, web scraping, certificate transparency logs, and various third-party data sources. It systematically discovers subdomains, IP addresses, and other assets associated with the target domain while respecting rate limits and avoiding detection."
          ]
        },
        {
          question: "How do I read the Amass output?",
          answers: [
            "Scan History shows the time, date, and results of previous scans. This helps track your reconnaissance progress and compare results across different scans.",
            "Raw Results shows the complete output of the Amass scan, including all discovered subdomains, IP addresses, and associated metadata. This is useful for detailed analysis and verification.",
            "DNS Records provides detailed DNS information for discovered subdomains, including A records, CNAME records, and other DNS configurations that help understand the infrastructure.",
            "Infrastructure View shows a comprehensive overview of the target's infrastructure, including cloud services, hosting providers, and other technical details about the discovered assets."
          ]
        }
      ]
    },
    subdomainScraping: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What are subdomain scraping tools and why do we need them?",
          answers: [
            "Subdomain scraping tools use various techniques to discover subdomains from public sources, web scraping, and third-party data. They complement Amass by finding additional subdomains that might have been missed.",
            "Each tool has its own strengths: Httpx finds live web servers, Gau discovers URLs from JavaScript files, Sublist3r uses multiple search engines, Assetfinder focuses on DNS enumeration, and CTL checks certificate transparency logs."
          ]
        },
        {
          question: "How do I use these tools effectively?",
          answers: [
            "Start with Httpx to identify live web servers, then use Gau to discover URLs from JavaScript files. Follow up with Sublist3r for search engine results, Assetfinder for DNS enumeration, and CTL for certificate transparency logs.",
            "After running each tool, review the results in their respective modals. Use the Consolidate button to combine all discovered subdomains into a single list, then run Httpx again to verify which ones are live web servers."
          ]
        }
      ]
    },
    bruteForce: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What is subdomain brute-forcing and why is it important?",
          answers: [
            "Subdomain brute-forcing is a technique that systematically tries different subdomain names against a domain to discover valid subdomains. This method can find subdomains that weren't discovered through passive reconnaissance or public sources.",
            "While this technique is more aggressive than passive methods, it's crucial for finding hidden or forgotten subdomains that might be vulnerable. It's particularly useful for discovering development, staging, or internal subdomains that might not be publicly advertised."
          ]
        },
        {
          question: "How do I use the brute-force tools effectively?",
          answers: [
            "Start with Subfinder for initial enumeration, then use ShuffleDNS for DNS-based brute-forcing. Follow up with CeWL to generate custom wordlists based on the target's content, and finally use GoSpider for crawling and discovering additional subdomains.",
            "After running each tool, review the results in their respective modals. Use the Consolidate button to combine all discovered subdomains into a single list, then run Httpx again to verify which ones are live web servers. This ensures you have a comprehensive list of valid subdomains."
          ]
        }
      ]
    },
    javascriptDiscovery: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What is JavaScript/Link Discovery and why is it important?",
          answers: [
            "JavaScript/Link Discovery is a technique that analyzes web applications' JavaScript files and HTML content to find hidden subdomains, endpoints, and other assets. This method is particularly effective because modern web applications often contain valuable information in their client-side code.",
            "This approach can discover subdomains that aren't visible through DNS enumeration or public sources, as they might be dynamically loaded or referenced in JavaScript code."
          ]
        },
        {
          question: "How do I use these tools effectively?",
          answers: [
            "Start with GoSpider to crawl the target's web applications and discover JavaScript files and links. Follow up with Subdomainizer to extract subdomains from JavaScript files and other web content. Finally, use Nuclei Screenshot to capture visual evidence of discovered assets.",
            "After running each tool, review the results in their respective modals. Use the Consolidate button to combine all discovered subdomains into a single list, then run Httpx again to verify which ones are live web servers. This ensures you have a comprehensive list of valid subdomains."
          ]
        }
      ]
    },
    decisionPoint: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What is the Decision Point and why is it important?",
          answers: [
            "The Decision Point is where you evaluate all the reconnaissance results and decide which discovered assets should be added as URL Scope Targets. This is a crucial step as it determines which assets you'll focus on during your bug bounty testing.",
            "At this stage, you should have a comprehensive list of live web servers from various discovery methods: Amass enumeration, subdomain scraping, brute-forcing, and JavaScript analysis. The Decision Point helps you organize and prioritize these assets for testing."
          ]
        },
        {
          question: "How do I evaluate and select targets effectively?",
          answers: [
            "Start by reviewing the consolidated list of discovered subdomains. Use the ROI Report to identify high-value targets based on factors like technology stack, security headers, and potential attack surface. Pay special attention to assets that might contain sensitive information or critical functionality.",
            "After identifying promising targets, use the 'Add URL Scope Target' button to add them to your scope. Consider factors like the target's importance to the organization, potential impact of vulnerabilities, and your testing priorities when selecting targets."
          ]
        }
      ]
    }
  };

  const currentSection = sections[section];

  return (
    <Accordion data-bs-theme="dark" className="mb-3">
      <Accordion.Item eventKey="0">
        <Accordion.Header className="fs-5">{currentSection.title}</Accordion.Header>
        <Accordion.Body className="bg-dark">
          <ListGroup as="ul" variant="flush">
            {currentSection.items.map((item, index) => (
              <ListGroup.Item key={index} as="li" className="bg-dark text-danger 5">
                {item.question}
                <ListGroup as="ul" variant="flush" className="mt-2">
                  {item.answers.map((answer, answerIndex) => (
                    <ListGroup.Item key={answerIndex} as="li" className="bg-dark text-white fst-italic fs-6">
                      {answer}{' '}
                      <a href="#" className="text-danger text-decoration-none">
                        Learn More
                      </a>
                    </ListGroup.Item>
                  ))}
                </ListGroup>
              </ListGroup.Item>
            ))}
          </ListGroup>
        </Accordion.Body>
      </Accordion.Item>
    </Accordion>
  );
};

export default HelpMeLearn; 