/**
 * Geo-blocking Module
 * Blocks requests based on country/region
 */

class GeoBlocker {
  constructor(options = {}) {
    this.blockedCountries = new Set(options.blockedCountries || []);
    this.allowedCountries = new Set(options.allowedCountries || []);
    this.blockedRegions = new Set(options.blockedRegions || []);
    this.useGeoIP = options.useGeoIP || false;
    this.geoIPService = options.geoIPService || 'ipapi';
    
    // Country code to name mapping (common ones)
    this.countryNames = {
      'US': 'United States', 'CN': 'China', 'RU': 'Russia', 'KP': 'North Korea',
      'IR': 'Iran', 'SY': 'Syria', 'CU': 'Cuba', 'SD': 'Sudan'
    };
  }

  /**
   * Get country from IP address
   * Uses free ipapi.co service (rate limited) or can be extended
   */
  async getCountryFromIP(ip) {
    // Handle localhost/private IPs
    if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || 
        ip.startsWith('10.') || ip.startsWith('172.')) {
      return { country: 'LOCAL', region: 'LOCAL' };
    }

    try {
      // Simple IP-based country detection using ipapi.co (free tier)
      const response = await fetch(`https://ipapi.co/${ip}/json/`);
      const data = await response.json();
      
      return {
        country: data.country_code,
        countryName: data.country_name,
        region: data.region,
        city: data.city,
        latitude: data.latitude,
        longitude: data.longitude
      };
    } catch (err) {
      console.error('GeoIP lookup failed:', err.message);
      return { country: 'UNKNOWN', region: 'UNKNOWN' };
    }
  }

  /**
   * Check if IP should be blocked based on geo
   */
  async checkIP(ip) {
    const geo = await this.getCountryFromIP(ip);
    
    const result = {
      blocked: false,
      reason: null,
      country: geo.country,
      countryName: geo.countryName,
      region: geo.region
    };

    // Check blocked countries
    if (this.blockedCountries.has(geo.country)) {
      result.blocked = true;
      result.reason = `Country ${geo.country} is blocked`;
      return result;
    }

    // Check blocked regions
    if (this.blockedRegions.has(geo.region)) {
      result.blocked = true;
      result.reason = `Region ${geo.region} is blocked`;
      return result;
    }

    // If allowed list is set, only allow those countries
    if (this.allowedCountries.size > 0 && !this.allowedCountries.has(geo.country)) {
      result.blocked = true;
      result.reason = `Country ${geo.country} is not in allowed list`;
      return result;
    }

    return result;
  }

  /**
   * Quick check using cached data (for middleware use)
   */
  checkCountry(countryCode) {
    if (this.blockedCountries.has(countryCode)) {
      return { blocked: true, reason: `Country ${countryCode} is blocked` };
    }
    
    if (this.allowedCountries.size > 0 && !this.allowedCountries.has(countryCode)) {
      return { blocked: true, reason: `Country ${countryCode} not allowed` };
    }

    return { blocked: false };
  }

  // Management methods
  blockCountry(countryCode) {
    this.blockedCountries.add(countryCode.toUpperCase());
  }

  unblockCountry(countryCode) {
    this.blockedCountries.delete(countryCode.toUpperCase());
  }

  allowCountry(countryCode) {
    this.allowedCountries.add(countryCode.toUpperCase());
  }

  removeAllowedCountry(countryCode) {
    this.allowedCountries.delete(countryCode.toUpperCase());
  }

  blockRegion(region) {
    this.blockedRegions.add(region);
  }

  unblockRegion(region) {
    this.blockedRegions.delete(region);
  }

  getBlockedCountries() {
    return Array.from(this.blockedCountries).map(code => ({
      code,
      name: this.countryNames[code] || code
    }));
  }

  getAllowedCountries() {
    return Array.from(this.allowedCountries).map(code => ({
      code,
      name: this.countryNames[code] || code
    }));
  }

  getBlockedRegions() {
    return Array.from(this.blockedRegions);
  }
}

module.exports = { GeoBlocker };
