require 'spec_helper'

describe Rack::Auth::SmD do

  describe "#initialize" do
    context "defaults" do
      its(:range){ should be Rack::Auth::SmD::DEFAULT_RANGE }
      its(:ms_per_unit){ should be Rack::Auth::SmD::MS_PER_HOUR }
    end

    context "with params" do
      it "accepts a range" do
        Rack::Auth::SmD.new({ range: (2 ** 32) }).range.should eq (2 ** 32)
      end

      it "accepts milliseconds per unit" do
        Rack::Auth::SmD.new({ ms_per_unit: 2000 }).ms_per_unit.should eq (2000)
      end
    end
  end

  describe "#range_in_ms" do
    its(:range_in_ms){ should be_kind_of Integer }
    its(:range_in_ms){ should eq (subject.range * subject.ms_per_unit) }
  end

  describe "#date" do
    it "should return a Time" do
      subject.date(-1 * (2 ** 15)).should be_kind_of Time
    end

    it "should support negative values down to min" do
      subject.date(-1 * (2 ** 15)).should eq Time.at(subject.min)
    end

    it "should support positive values up to max" do
      subject.date((2 ** 16) - 1).should eq Time.at(subject.max)
    end
  end

  describe "#min" do
    it "should be -1/2 the range" do
      subject.min.should eq subject.date(-1 * (subject.range / 2))
    end
  end

  describe "#max" do
    it "should be one less than the range" do
      subject.max.should eq subject.date(subject.range - 1)
    end
  end

  describe "#at" do
    it "supports negative numbers" do
      subject.at(-1 * (2 ** 15)).should eq subject.min.to_i
    end
  end

end